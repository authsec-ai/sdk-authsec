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

const (
	defaultScopeMatrixTTL  = 5 * time.Minute
	defaultMaxStaleAge     = 30 * time.Minute
	defaultRetryBackoff    = 30 * time.Second
)

// sdkPolicyResponse matches the JSON returned by
// GET /authsec/resource-servers/:id/sdk-policy
type sdkPolicyResponse struct {
	Tools      map[string][]string `json:"tools"`
	FetchedAt  string              `json:"fetched_at"`
	TTLSeconds int                 `json:"ttl_seconds"`
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

	mu           sync.RWMutex
	toolMap      ToolScopeMap
	fetchedAt    time.Time
	lastErr      error
	lastErrAt    time.Time
	nextRefreshAt time.Time // earliest time a new background refresh may be attempted

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
func (c *ScopeMatrixClient) Fetch(ctx context.Context) (ToolScopeMap, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("scope matrix fetch: %w", err)
	}
	req.SetBasicAuth(c.clientID, c.clientSecret)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("scope matrix fetch: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("scope matrix fetch: HTTP %d", resp.StatusCode)
	}

	var payload sdkPolicyResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, fmt.Errorf("scope matrix decode: %w", err)
	}

	toolMap := make(ToolScopeMap, len(payload.Tools))
	for name, scopes := range payload.Tools {
		toolMap[name] = scopes
	}
	return toolMap, nil
}

// FetchAndCache fetches the mapping and stores it in the cache.
// FetchAndCache owns all cache state updates:
//   - On success: sets toolMap, fetchedAt; clears lastErr, lastErrAt, nextRefreshAt.
//   - On failure: sets lastErr, lastErrAt, nextRefreshAt (retry cooldown); leaves toolMap/fetchedAt unchanged.
func (c *ScopeMatrixClient) FetchAndCache(ctx context.Context) error {
	toolMap, err := c.Fetch(ctx)
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if err != nil {
		c.lastErr = err
		c.lastErrAt = now
		c.nextRefreshAt = now.Add(c.retryBackoff)
		return err
	}
	c.toolMap = toolMap
	c.fetchedAt = now
	c.lastErr = nil
	c.lastErrAt = time.Time{}
	c.nextRefreshAt = time.Time{} // zero = no cooldown; healthy fetches run on TTL schedule
	return nil
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
		HasData:   c.toolMap != nil,
		FetchedAt: c.fetchedAt,
		StaleAge:  time.Since(c.fetchedAt),
		LastErr:   c.lastErr,
		LastErrAt: c.lastErrAt,
	}
}
