package authsec

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// PollOptions configures PollUntilApproved. Zero values fall back to defaults
// (Interval 3s, Timeout 300s).
type PollOptions struct {
	Interval time.Duration
	Timeout  time.Duration
}

// PollUntilApproved polls an access-request status URL until access is approved
// and then returns a fresh access token. It is the Go parity of the Python
// SDK's poll_until_approved.
//
// Typical use after AccessFor returns a *PendingApprovalError:
//
//	tok, err := ai.AccessFor(ctx, resource, authsec.WithUserSession(idToken))
//	var pending *authsec.PendingApprovalError
//	if errors.As(err, &pending) {
//	    tok, err = authsec.PollUntilApproved(ctx, ai, resource, pending.StatusURL, nil,
//	        authsec.WithUserSession(idToken))
//	}
//
// The AccessForOption args are forwarded to the final AccessFor call once
// approved (pass the same options used originally, e.g. WithUserSession).
//
// Returns *ApprovalDeniedError if an admin declines, *ConnectionRevokedError if
// access is revoked, ctx.Err() if the context is cancelled, or a timeout error
// if Timeout elapses while still pending.
func PollUntilApproved(
	ctx context.Context,
	ai *AgentIdentity,
	resource, statusURL string,
	opts *PollOptions,
	o ...AccessForOption,
) (string, error) {
	interval := 3 * time.Second
	timeout := 300 * time.Second
	if opts != nil {
		if opts.Interval > 0 {
			interval = opts.Interval
		}
		if opts.Timeout > 0 {
			timeout = opts.Timeout
		}
	}
	deadline := time.Now().Add(timeout)

	for {
		// A transient poll error is non-fatal — keep polling until the deadline.
		if status, err := ai.pollStatus(ctx, statusURL); err == nil {
			switch status {
			case "approved":
				ai.ClearCache(resource)
				return ai.AccessFor(ctx, resource, o...)
			case "denied":
				return "", newApprovalDeniedError()
			case "revoked":
				return "", newConnectionRevokedError()
				// "pending" / unknown → keep polling
			}
		}

		if time.Now().After(deadline) {
			return "", fmt.Errorf(
				"poll_until_approved: timed out after %s waiting for approval of access to %s",
				timeout, resource,
			)
		}

		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(interval):
		}
	}
}

// pollStatus fetches an access-request status document and returns its status
// field ("pending" | "approved" | "denied" | "revoked").
func (a *AgentIdentity) pollStatus(ctx context.Context, statusURL string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, statusURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("status poll returned HTTP %d", resp.StatusCode)
	}

	var body struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", err
	}
	return body.Status, nil
}
