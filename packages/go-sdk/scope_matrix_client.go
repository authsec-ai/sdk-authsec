package authsec

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Tightened defaults in v0.3.1 to close the "revoke a permission, user still has access
// for 5 min" gap. With these values, admin RBAC changes propagate to MCP servers within
// <= 30 s in the common case; stale-with-error window is capped at 2 min so a misbehaving
// AS doesn't leave a server running on outdated policy for half an hour. Customers who
// want the old behavior for performance can override via Config.ScopeMatrixTTL.
const (
	defaultScopeMatrixTTL = 30 * time.Second
	defaultMaxStaleAge    = 2 * time.Minute
	defaultRetryBackoff   = 10 * time.Second
)

// toolPolicyEntry matches the per-tool entry in the `tool_policy` array.
// This is the authoritative shape; the legacy `tools` flat map is still
// emitted by the backend for back-compat but consumers MUST NOT infer
// is_public from it.
type toolPolicyEntry struct {
	Name           string   `json:"name"`
	IsPublic       bool     `json:"is_public"`
	RequiredScopes []string `json:"required_scopes"`
}

// sdkPolicyResponse matches the JSON returned by
// GET /authsec/resource-servers/:id/sdk-policy
//
// Field semantics (per the canonical contract):
//   - State == "ready" AND PolicyComplete == true → use ToolPolicy as authoritative.
//   - PolicyComplete == false → treat as deny-all; do NOT cache as a successful fetch.
//     The Reason field carries the lifecycle code (rs_needs_setup, rs_scan_failed,
//     rs_pending_scan) for observability.
//   - Tools is the legacy flat scope-only map preserved for older SDK builds.
//     New code MUST read ToolPolicy instead — an empty array in Tools does NOT
//     imply public; is_public lives only on ToolPolicy.
type sdkPolicyResponse struct {
	State          string              `json:"state"`
	PolicyComplete bool                `json:"policy_complete"`
	Reason         string              `json:"reason"`
	RSID           string              `json:"rs_id"`
	Generation     int64               `json:"generation"`
	// ScopesSupported: authoritative scope list for this RS, served straight
	// from the AuthSec admin DB. The SDK feeds this into the PRM (RFC 9728)
	// scopes_supported field so admin-side changes propagate to MCP clients
	// without a code change. Empty array is legitimate (RS has no scopes yet).
	ScopesSupported []string            `json:"scopes_supported"`
	Tools           map[string][]string `json:"tools"` // legacy back-compat
	ToolPolicy      []toolPolicyEntry   `json:"tool_policy"`
	FetchedAt       string              `json:"fetched_at"`
	TTLSeconds      int                 `json:"ttl_seconds"`
}

// ErrPolicyIncomplete is returned by Fetch / FetchAndCache when the backend
// signals policy_complete=false. Callers must treat this as deny-all and
// must NOT fall back to a stale local cache for tool authorization.
type ErrPolicyIncomplete struct {
	State  string
	Reason string
}

func (e ErrPolicyIncomplete) Error() string {
	if e.Reason == "" {
		return fmt.Sprintf("authsec policy incomplete: state=%s", e.State)
	}
	return fmt.Sprintf("authsec policy incomplete: state=%s reason=%s", e.State, e.Reason)
}

// CacheStatus describes the current state of the scope matrix cache.
type CacheStatus struct {
	// HasData is true if the cache has been populated at least once.
	HasData bool
	// FetchedAt is the timestamp of the last successful fetch; zero if never fetched.
	FetchedAt time.Time
	// StaleAge is how long ago the last successful fetch occurred.
	StaleAge time.Duration
	// LastErr is the last fetch error; nil after a successful fetch clears it.
	LastErr error
	// LastErrAt is the timestamp of the last error; zero if LastErr is nil.
	LastErrAt time.Time
	// PolicyState is the last-observed RS lifecycle state ("ready", "needs_setup",
	// "scan_failed", "pending_scan"). Empty until the first fetch attempt.
	PolicyState string
	// PolicyComplete is true iff the last response was a usable policy.
	// false means the SDK is enforcing deny-all because the RS is not ready.
	PolicyComplete bool
	// Generation is the monotonic policy version from the last successful fetch.
	Generation int64
}

// ScopeMatrixClient fetches and caches tool→scope mappings from AuthSec.
// It uses the same Basic-auth credentials as introspection.
type ScopeMatrixClient struct {
	endpoint     string // full URL: {base}/authsec/resource-servers/{id}/sdk-policy
	clientID     string
	clientSecret string
	httpClient   *http.Client
	ttl          time.Duration
	maxStaleAge  time.Duration
	retryBackoff time.Duration

	mu             sync.RWMutex
	toolMap        ToolScopeMap
	// scopesSupported: authoritative scope list cached from AuthSec, used by
	// the PRM builder. nil = never fetched (boot before first refresh);
	// empty slice = fetched but no scopes published yet — distinguishable so
	// the PRM builder can fall back to local config only when truly absent.
	scopesSupported []string
	fetchedAt      time.Time
	lastErr        error
	lastErrAt      time.Time
	nextRefreshAt  time.Time // earliest time a new background refresh may be attempted
	policyState    string    // last-observed lifecycle state, for observability
	policyComplete bool      // false = deny-all enforced
	generation     int64     // monotonic policy version

	refreshing atomic.Bool // CAS gate: only one background refresh at a time
}

// NewScopeMatrixClient creates a client that fetches tool→scope mappings.
// Returns nil if the config does not have enough information for remote fetch
// (missing ResourceServerID or AuthorizationServer).
func NewScopeMatrixClient(cfg Config) *ScopeMatrixClient {
	if cfg.ResourceServerID == "" || cfg.AuthorizationServer == "" {
		return nil
	}
	if cfg.IntrospectionClientID == "" || cfg.IntrospectionClientSecret == "" {
		return nil
	}
	base := strings.TrimRight(cfg.AuthorizationServer, "/")
	endpoint := fmt.Sprintf("%s/authsec/resource-servers/%s/sdk-policy", base, cfg.ResourceServerID)

	ttl := cfg.ScopeMatrixTTL
	if ttl == 0 {
		ttl = defaultScopeMatrixTTL
	}

	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}

	return &ScopeMatrixClient{
		endpoint:     endpoint,
		clientID:     cfg.IntrospectionClientID,
		clientSecret: cfg.IntrospectionClientSecret,
		httpClient:   client,
		ttl:          ttl,
		maxStaleAge:  defaultMaxStaleAge,
		retryBackoff: defaultRetryBackoff,
	}
}

// Fetch retrieves the tool→scope mapping from AuthSec.
//
// Returns ErrPolicyIncomplete when the backend signals policy_complete=false.
// The returned ToolScopeMap is nil in that case — callers must treat this
// as deny-all. The error carries the lifecycle state for observability.
//
// On success, the map is built from `tool_policy` (the authoritative array),
// not the legacy `tools` flat map:
//   - is_public=true               → empty-slice entry (ToolPolicyPublic)
//   - is_public=false, scopes=[a]  → ["a"] entry (ToolPolicyScoped)
//   - is_public=false, scopes=[]   → tool OMITTED (ToolPolicyAbsent → deny)
func (c *ScopeMatrixClient) Fetch(ctx context.Context) (ToolScopeMap, *sdkPolicyResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.endpoint, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("scope matrix fetch: %w", err)
	}
	req.SetBasicAuth(c.clientID, c.clientSecret)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("scope matrix fetch: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("scope matrix fetch: HTTP %d", resp.StatusCode)
	}

	var payload sdkPolicyResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, nil, fmt.Errorf("scope matrix decode: %w", err)
	}

	// Back-compat shim: pre-migration backends emit the legacy shape
	//   {"tools": {...}}
	// without state/policy_complete/tool_policy. Treat that exact shape
	// (no state field AND no tool_policy AND tools map populated) as a
	// legacy ready response. New backends always set policy_complete
	// explicitly so any half-populated response is still treated as deny-all.
	legacyShape := payload.State == "" && len(payload.ToolPolicy) == 0 && len(payload.Tools) > 0
	if legacyShape {
		payload.State = "ready"
		payload.PolicyComplete = true
	}

	// Deny-all signal from backend: never produce a usable map.
	if !payload.PolicyComplete {
		return nil, &payload, ErrPolicyIncomplete{State: payload.State, Reason: payload.Reason}
	}

	// Build the authoritative map from tool_policy when present, otherwise
	// fall back to the legacy `tools` map (back-compat with older backends).
	// New code path: tool_policy carries explicit is_public.
	// Legacy code path: tools map alone, where empty-slice means public
	// (matches the historical ToolScopeMap encoding).
	var toolMap ToolScopeMap
	if len(payload.ToolPolicy) > 0 {
		toolMap = make(ToolScopeMap, len(payload.ToolPolicy))
		for _, t := range payload.ToolPolicy {
			switch {
			case t.IsPublic:
				toolMap[t.Name] = []string{} // ToolPolicyPublic
			case len(t.RequiredScopes) > 0:
				toolMap[t.Name] = t.RequiredScopes // ToolPolicyScoped
				// else: omit → ToolPolicyAbsent → deny
			}
		}
	} else {
		// Legacy: copy the flat map verbatim. Empty slice = public per the
		// existing ToolScopeMap convention.
		toolMap = make(ToolScopeMap, len(payload.Tools))
		for name, scopes := range payload.Tools {
			toolMap[name] = scopes
		}
	}
	return toolMap, &payload, nil
}

// FetchAndCache fetches the mapping and stores it in the cache.
// FetchAndCache owns all cache state updates:
//   - On success (policy_complete=true): sets toolMap, fetchedAt, generation,
//     policyState=state, policyComplete=true; clears lastErr/lastErrAt/nextRefreshAt.
//   - On policy_complete=false: clears toolMap so subsequent GetCached returns
//     deny-all; records policyState/Reason; sets lastErr to ErrPolicyIncomplete
//     so retries happen on the standard cooldown.
//   - On transport/decode failure: sets lastErr, lastErrAt, nextRefreshAt;
//     leaves toolMap/fetchedAt unchanged so previously-good policy keeps serving
//     until maxStaleAge.
func (c *ScopeMatrixClient) FetchAndCache(ctx context.Context) error {
	toolMap, payload, err := c.Fetch(ctx)
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()

	// Transport/decode error: don't touch toolMap; let stale serving rules apply.
	if err != nil && payload == nil {
		c.lastErr = err
		c.lastErrAt = now
		c.nextRefreshAt = now.Add(c.retryBackoff)
		return err
	}

	// Backend responded; update observability fields regardless of completeness.
	c.policyState = payload.State
	c.generation = payload.Generation

	// Policy-incomplete: enforce deny-all by clearing the cached map.
	// We deliberately do NOT keep the previous map — once the backend signals
	// the RS is not ready, the SDK must stop authorizing tools immediately.
	// Clear scopesSupported too: an RS that's not ready hasn't published any
	// scopes, and the PRM should reflect that.
	if err != nil {
		c.toolMap = nil
		c.scopesSupported = nil
		c.fetchedAt = time.Time{}
		c.policyComplete = false
		c.lastErr = err
		c.lastErrAt = now
		c.nextRefreshAt = now.Add(c.retryBackoff)
		return err
	}

	c.toolMap = toolMap
	// Backend always emits scopes_supported on policy_complete=true. If a
	// pre-migration backend omits it (nil), keep the previous cached value
	// so the PRM keeps publishing what it last knew.
	if payload.ScopesSupported != nil {
		// Copy to defend against later mutation of the payload.
		scopes := make([]string, len(payload.ScopesSupported))
		copy(scopes, payload.ScopesSupported)
		c.scopesSupported = scopes
	}
	c.fetchedAt = now
	c.policyComplete = true
	c.lastErr = nil
	c.lastErrAt = time.Time{}
	c.nextRefreshAt = time.Time{} // zero = no cooldown; healthy fetches run on TTL schedule
	return nil
}

// GetScopesSupported returns the cached authoritative scopes_supported list.
//
// Triggers a background refresh on TTL expiry, same as GetCached.
//
// Returns nil when:
//   - the cache has never been populated successfully (boot before first refresh),
//   - or the cache exceeded maxStaleAge with the last refresh in error.
//
// Callers (the PRM builder) should fall back to cfg.SupportedScopes when this
// returns nil so the server still serves a metadata document at boot.
//
// Admin adds/removes a scope in the AuthSec UI → SDK picks it up on next
// matrix refresh (TTL ≤ 5 min) → PRM auto-updates → OAuth client sees it.
// **No code change in the MCP server.**
func (c *ScopeMatrixClient) GetScopesSupported(ctx context.Context) []string {
	c.mu.RLock()
	scopes := c.scopesSupported
	fetchedAt := c.fetchedAt
	lastErr := c.lastErr
	nextRefreshAt := c.nextRefreshAt
	c.mu.RUnlock()

	now := time.Now()
	age := now.Sub(fetchedAt)
	expired := age > c.ttl

	if expired && now.After(nextRefreshAt) && c.refreshing.CompareAndSwap(false, true) {
		go func() {
			bgCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_ = c.FetchAndCache(bgCtx)
			c.refreshing.Store(false)
		}()
	}

	// Same stale-then-error rule as GetCached: never serve data older than
	// maxStaleAge with a known error condition.
	if scopes == nil && lastErr != nil {
		return nil
	}
	if scopes != nil && lastErr != nil && age > c.maxStaleAge {
		return nil
	}
	if scopes == nil {
		return nil
	}
	out := make([]string, len(scopes))
	copy(out, scopes)
	return out
}

// GetCached returns the cached tool→scope mapping or an error.
//
// If the cache is expired and outside the retry cooldown window, a single
// background refresh is triggered (CAS gate prevents concurrent re-triggering).
//
// Returns an error if:
//   - The cache was never populated and the last fetch errored.
//   - The cache is older than maxStaleAge AND the last fetch errored (bounded stale serving).
func (c *ScopeMatrixClient) GetCached(ctx context.Context) (ToolScopeMap, error) {
	c.mu.RLock()
	toolMap := c.toolMap
	fetchedAt := c.fetchedAt
	lastErr := c.lastErr
	nextRefreshAt := c.nextRefreshAt
	c.mu.RUnlock()

	now := time.Now()
	age := now.Sub(fetchedAt)
	expired := age > c.ttl

	if expired && now.After(nextRefreshAt) && c.refreshing.CompareAndSwap(false, true) {
		go func() {
			bgCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_ = c.FetchAndCache(bgCtx) // state updates handled inside FetchAndCache
			c.refreshing.Store(false)
		}()
	}

	// Cache never populated and last fetch errored.
	if toolMap == nil && lastErr != nil {
		return nil, lastErr
	}

	// Cache is stale beyond maxStaleAge and last refresh errored: refuse indefinitely stale data.
	if toolMap != nil && lastErr != nil && age > c.maxStaleAge {
		return nil, fmt.Errorf("scope matrix cache stale (age: %v) and last refresh failed: %w", age, lastErr)
	}

	return toolMap, nil
}

// CacheStatus returns a snapshot of the current cache state.
func (c *ScopeMatrixClient) CacheStatus() CacheStatus {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return CacheStatus{
		HasData:        c.toolMap != nil,
		FetchedAt:      c.fetchedAt,
		StaleAge:       time.Since(c.fetchedAt),
		LastErr:        c.lastErr,
		LastErrAt:      c.lastErrAt,
		PolicyState:    c.policyState,
		PolicyComplete: c.policyComplete,
		Generation:     c.generation,
	}
}
