package libmotleycue

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestGetUserErrorCategories verifies that getUser maps motley_cue's HTTP
// status codes onto the right sentinel category, so the CA can tell a rejected
// token (401) apart from a genuine authorization failure (403) and from an
// unreachable/unusable backend. It also checks that the upstream detail is
// preserved in the wrapped error (for server logs) without the caller having to
// parse strings.
func TestGetUserErrorCategories(t *testing.T) {
	tests := []struct {
		name    string
		status  int
		body    string
		wantIs  error
		notIs   error
		wantMsg string // substring expected in the wrapped error (detail preserved)
	}{
		{
			name:    "401 is a rejected token",
			status:  http.StatusUnauthorized,
			body:    `{"detail":"token expired"}`,
			wantIs:  ErrTokenRejected,
			notIs:   ErrForbidden,
			wantMsg: "token expired",
		},
		{
			name:    "403 is forbidden",
			status:  http.StatusForbidden,
			body:    `{"detail":"user suspended"}`,
			wantIs:  ErrForbidden,
			notIs:   ErrTokenRejected,
			wantMsg: "user suspended",
		},
		{
			name:   "404 is an upstream problem",
			status: http.StatusNotFound,
			body:   `{"detail":"not found"}`,
			wantIs: ErrUpstream,
			notIs:  ErrTokenRejected,
		},
		{
			name:   "500 is an upstream problem",
			status: http.StatusInternalServerError,
			body:   `boom`,
			wantIs: ErrUpstream,
			notIs:  ErrForbidden,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()

			_, err := NewClient(srv.URL).GetUserDeploy("some-token")
			if err == nil {
				t.Fatalf("expected error for status %d", tc.status)
			}
			if !errors.Is(err, tc.wantIs) {
				t.Errorf("errors.Is(%v, %v) = false, want true", err, tc.wantIs)
			}
			if tc.notIs != nil && errors.Is(err, tc.notIs) {
				t.Errorf("errors.Is(%v, %v) = true, want false", err, tc.notIs)
			}
			if tc.wantMsg != "" && !strings.Contains(err.Error(), tc.wantMsg) {
				t.Errorf("error %q does not preserve upstream detail %q", err.Error(), tc.wantMsg)
			}
		})
	}
}

// TestGetUserTransportErrorIsUpstream verifies that a transport-level failure
// (server unreachable) is categorised as ErrUpstream rather than looking like
// an authorization failure.
func TestGetUserTransportErrorIsUpstream(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL
	srv.Close() // close immediately so the address refuses connections

	_, err := NewClient(url).GetUserStatus("some-token")
	if err == nil {
		t.Fatal("expected error when motley_cue is unreachable")
	}
	if !errors.Is(err, ErrUpstream) {
		t.Errorf("errors.Is(%v, ErrUpstream) = false, want true", err)
	}
	if errors.Is(err, ErrTokenRejected) || errors.Is(err, ErrForbidden) {
		t.Errorf("transport failure must not be classified as an auth failure: %v", err)
	}
}
