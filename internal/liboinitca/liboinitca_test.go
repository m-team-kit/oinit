package liboinitca

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// stripScheme returns the host[:port] part of an httptest server URL so it can
// be handed to NewClient as an implicit-scheme address.
func stripScheme(url string) string {
	return strings.TrimPrefix(url, "http://")
}

// TestGetHostImplicitSchemeSkipsPlaintext verifies that a client built from an
// implicit-scheme address never falls back to a plaintext http:// request for
// the trust-anchor fetch: the https:// attempt fails (no TLS on the test
// server) and the http:// attempt must be skipped rather than tried.
func TestGetHostImplicitSchemeSkipsPlaintext(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := NewClient(stripScheme(srv.URL)) // implicit scheme: https first, http fallback
	if c.explicitScheme {
		t.Fatal("expected implicit scheme")
	}

	if _, err := c.GetHost("example.com"); err == nil {
		t.Fatal("expected error when only plaintext fallback is available")
	}
	if got := atomic.LoadInt32(&hits); got != 0 {
		t.Fatalf("plaintext endpoint was contacted %d time(s); token/anchor must never traverse implicit http", got)
	}
}

// TestPostCertificateImplicitSchemeSkipsPlaintext is the token-carrying
// equivalent of the above for the certificate request.
func TestPostCertificateImplicitSchemeSkipsPlaintext(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	c := NewClient(stripScheme(srv.URL))

	if _, err := c.PostHostCertificate("example.com", "ssh-ed25519 AAAA", "secret-token", ""); err == nil {
		t.Fatal("expected error when only plaintext fallback is available")
	}
	if got := atomic.LoadInt32(&hits); got != 0 {
		t.Fatalf("plaintext endpoint received the token %d time(s); it must never be sent over implicit http", got)
	}
}

// TestPostCertificateDoesNotFollowRedirect verifies that a 307 redirect is not
// followed, so the request body (which carries the access token) is never
// re-sent to the redirect target (an https->http downgrade vector).
func TestPostCertificateDoesNotFollowRedirect(t *testing.T) {
	var collectorHits int32
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&collectorHits, 1)
		w.WriteHeader(http.StatusCreated)
	}))
	defer collector.Close()

	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, collector.URL+"/steal", http.StatusTemporaryRedirect)
	}))
	defer primary.Close()

	// Explicit http scheme so the plaintext guard does not short-circuit the
	// request; we are isolating redirect behaviour here.
	c := NewClient(primary.URL)
	if !c.explicitScheme {
		t.Fatal("expected explicit scheme")
	}

	if _, err := c.PostHostCertificate("example.com", "ssh-ed25519 AAAA", "secret-token", ""); err == nil {
		t.Fatal("expected error: a redirect must fail the request, not be followed")
	}
	if got := atomic.LoadInt32(&collectorHits); got != 0 {
		t.Fatalf("redirect target received the token %d time(s); redirects must not be followed", got)
	}
}

// TestExplicitHttpIsHonoured confirms the operator opt-in still works: an
// explicit http:// CA reaches the server (and the token is delivered there).
func TestExplicitHttpIsHonoured(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"certificate":"cert-data"}`))
	}))
	defer srv.Close()

	c := NewClient(srv.URL) // explicit http://
	res, err := c.PostHostCertificate("example.com", "ssh-ed25519 AAAA", "secret-token", "")
	if err != nil {
		t.Fatalf("unexpected error for explicit http CA: %v", err)
	}
	if res.Certificate != "cert-data" {
		t.Fatalf("got certificate %q, want %q", res.Certificate, "cert-data")
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Fatalf("explicit http endpoint hit %d time(s), want 1", got)
	}
}
