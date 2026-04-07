package oidc

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	WELL_KNOWN_PATH    = "/.well-known/openid-configuration"
	USERINFO_TIMEOUT   = 10 * time.Second
	MAX_RESPONSE_SIZE  = 64 * 1024 // 64KB
)

// OpenIDConfiguration represents the relevant fields from an OpenID Connect
// discovery document.
type OpenIDConfiguration struct {
	UserinfoEndpoint string `json:"userinfo_endpoint"`
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
	issuerURL = strings.TrimSuffix(issuerURL, "/")
	discoveryURL := issuerURL + WELL_KNOWN_PATH

	client := &http.Client{Timeout: USERINFO_TIMEOUT}
	resp, err := client.Get(discoveryURL)
	if err != nil {
		return "", fmt.Errorf("GET %s: %w", discoveryURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GET %s returned status %d", discoveryURL, resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, MAX_RESPONSE_SIZE))
	if err != nil {
		return "", fmt.Errorf("reading discovery document: %w", err)
	}

	var config OpenIDConfiguration
	if err := json.Unmarshal(body, &config); err != nil {
		return "", fmt.Errorf("parsing discovery document: %w", err)
	}

	if config.UserinfoEndpoint == "" {
		return "", errors.New("discovery document does not contain userinfo_endpoint")
	}

	return config.UserinfoEndpoint, nil
}

// fetchUserinfo calls the userinfo endpoint with the given access token and
// returns the subject claim.
func fetchUserinfo(userinfoURL string, accessToken string) (string, error) {
	client := &http.Client{Timeout: USERINFO_TIMEOUT}

	req, err := http.NewRequest(http.MethodGet, userinfoURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := client.Do(req)
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
