package oidc

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	WELL_KNOWN_PATH   = "/.well-known/openid-configuration"
	USERINFO_TIMEOUT  = 10 * time.Second
	MAX_RESPONSE_SIZE = 64 * 1024 // 64KB
)

// httpClient is used for discovery and userinfo requests. It refuses to follow
// redirects: the userinfo request carries the user's Bearer access token, and a
// followed redirect could bounce that token to an attacker-controlled or
// plaintext location (an https->http downgrade). A redirect therefore surfaces
// as a non-200 status and the request fails cleanly instead.
var httpClient = &http.Client{
	Timeout: USERINFO_TIMEOUT,
	CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

// requireHTTPS returns an error unless rawURL is a well-formed https:// URL.
// The access token must never traverse a plaintext channel, so both the issuer
// and the discovered userinfo endpoint are required to use TLS.
func requireHTTPS(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL %q: %w", rawURL, err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("URL must use https, got %q", rawURL)
	}
	return nil
}

// OpenIDConfiguration represents the relevant fields from an OpenID Connect
// discovery document.
type OpenIDConfiguration struct {
	Issuer           string `json:"issuer"`
	UserinfoEndpoint string `json:"userinfo_endpoint"`
	JwksURI          string `json:"jwks_uri"`
}

// fetchDiscovery retrieves and parses the OpenID Connect discovery document for
// issuerURL. The issuer must use https so the document (which advertises the
// endpoints the access token is later sent to) cannot be read or tampered with
// on the wire.
func fetchDiscovery(issuerURL string) (OpenIDConfiguration, error) {
	var config OpenIDConfiguration

	if err := requireHTTPS(issuerURL); err != nil {
		return config, fmt.Errorf("issuer: %w", err)
	}

	discoveryURL := strings.TrimSuffix(issuerURL, "/") + WELL_KNOWN_PATH

	resp, err := httpClient.Get(discoveryURL)
	if err != nil {
		return config, fmt.Errorf("GET %s: %w", discoveryURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return config, fmt.Errorf("GET %s returned status %d", discoveryURL, resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, MAX_RESPONSE_SIZE))
	if err != nil {
		return config, fmt.Errorf("reading discovery document: %w", err)
	}

	if err := json.Unmarshal(body, &config); err != nil {
		return config, fmt.Errorf("parsing discovery document: %w", err)
	}

	return config, nil
}

// UserinfoResponse represents the relevant fields from an OpenID Connect
// userinfo response.
type UserinfoResponse struct {
	Sub string `json:"sub"`
}

// LookupSubject queries the OpenID Connect provider's userinfo endpoint to
// obtain the subject claim for the given access token. The issuer URL is used
// to discover the userinfo endpoint via .well-known/openid-configuration.
//
// Returns the subject string or an error if the lookup fails.
func LookupSubject(issuerURL string, accessToken string) (string, error) {
	if issuerURL == "" || accessToken == "" {
		return "", errors.New("issuer URL and access token are required")
	}

	// Discover the userinfo endpoint
	userinfoURL, err := discoverUserinfoEndpoint(issuerURL)
	if err != nil {
		return "", fmt.Errorf("discovery failed: %w", err)
	}

	// Call the userinfo endpoint
	sub, err := fetchUserinfo(userinfoURL, accessToken)
	if err != nil {
		return "", fmt.Errorf("userinfo request failed: %w", err)
	}

	return sub, nil
}

// discoverUserinfoEndpoint fetches the OpenID Connect discovery document and
// extracts the userinfo_endpoint.
func discoverUserinfoEndpoint(issuerURL string) (string, error) {
	config, err := fetchDiscovery(issuerURL)
	if err != nil {
		return "", err
	}

	if config.UserinfoEndpoint == "" {
		return "", errors.New("discovery document does not contain userinfo_endpoint")
	}
	// The discovery document is attacker-influenced if the provider is
	// compromised or MITM'd; never send the access token to a plaintext
	// userinfo endpoint it advertises.
	if err := requireHTTPS(config.UserinfoEndpoint); err != nil {
		return "", fmt.Errorf("userinfo_endpoint: %w", err)
	}

	return config.UserinfoEndpoint, nil
}

// fetchUserinfo calls the userinfo endpoint with the given access token and
// returns the subject claim.
func fetchUserinfo(userinfoURL string, accessToken string) (string, error) {
	req, err := http.NewRequest(http.MethodGet, userinfoURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("GET %s: %w", userinfoURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GET %s returned status %d", userinfoURL, resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, MAX_RESPONSE_SIZE))
	if err != nil {
		return "", fmt.Errorf("reading userinfo response: %w", err)
	}

	var userinfo UserinfoResponse
	if err := json.Unmarshal(body, &userinfo); err != nil {
		return "", fmt.Errorf("parsing userinfo response: %w", err)
	}

	if userinfo.Sub == "" {
		return "", errors.New("userinfo response does not contain sub claim")
	}

	return userinfo.Sub, nil
}
