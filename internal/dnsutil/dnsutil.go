package dnsutil

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/lbrocke/oinit/internal/util"
	"github.com/lbrocke/oinit/pkg/log"
)

const (
	TXT_PREFIX = "_oinit-ca."
	// Cache durations (in seconds, will be multiplied by time.Second in cache.Set)
	CACHE_DURATION     = 300 // Cache DNS lookups for 5 minutes
	CACHE_DURATION_NEG = 60  // Cache negative results for 1 minute

	// HTTPS discovery settings
	HTTPS_PORT          = "443"
	HTTPS_ENDPOINT      = "/oinit/"
	HTTPS_TIMEOUT       = 5 * time.Second
	HTTPS_MAX_BODY_SIZE = 1024 // 1KB should be enough for version response
)

var (
	// Package-level cache for DNS lookups
	caCache = util.NewTimedCache[string, string]()
)

// LookupCA tries to find the CA for a given ssh server host name by querying
// the domain name system and, if DNS fails, by probing HTTPS endpoints.
//
// Discovery Process:
// 1. DNS TXT Record Lookup (preferred method):
//    - For hostname "login.example.com", looks up TXT record at "_oinit-ca.login.example.com"
//    - If not found, tries parent domain: "_oinit-ca.example.com"
//    - Wildcard hosts (*.example.com) are normalized by stripping the "*." prefix
//
// 2. HTTPS Endpoint Discovery (fallback method):
//    - If both DNS lookups fail, tries HTTPS probes:
//      a) https://login.example.com:443/oinit/
//      b) https://example.com:443/oinit/
//    - A successful response from /oinit/ indicates the host is running oinit-ca
//
// Results are cached for CACHE_DURATION seconds to reduce DNS queries. The function
// validates that the TXT record or discovered URL contains a valid HTTP/HTTPS URL.
// If multiple TXT records exist, only the first is used and a warning is logged.
func LookupCA(host string) (string, error) {
	// Check cache first
	if cachedCA, found := caCache.Get(host); found {
		if cachedCA == "" {
			// Cached negative result
			return "", errors.New("no CA found for this host (cached)")
		}
		return cachedCA, nil
	}

	lookup1, _ := strings.CutPrefix(host, "*.")

	// Phase 1: DNS TXT Record Lookups
	log.LogDebug(fmt.Sprintf("Attempting DNS TXT lookup for %s", TXT_PREFIX+lookup1))

	// Try full hostname first
	records, err := net.LookupTXT(TXT_PREFIX + lookup1)
	if err == nil && len(records) > 0 {
		if ca, validateErr := validateAndSelectCA(records, TXT_PREFIX+lookup1); validateErr == nil {
			log.LogInfo(fmt.Sprintf("Determined CA: %s (via DNS TXT)", ca))
			log.LogDebug(fmt.Sprintf("Found CA via DNS TXT record at %s: %s", TXT_PREFIX+lookup1, ca))
			caCache.Set(host, ca, time.Duration(CACHE_DURATION))
			return ca, nil
		} else {
			// Cache the error for a shorter duration
			caCache.Set(host, "", time.Duration(CACHE_DURATION_NEG))
			return "", validateErr
		}
	} else if err != nil {
		log.LogDebug(fmt.Sprintf("DNS TXT lookup failed for %s: %v", TXT_PREFIX+lookup1, err))
	}

	// Remove subdomain and try parent domain
	_, lookup2, foundParent := strings.Cut(lookup1, ".")
	var hasParent bool
	if foundParent && strings.Count(lookup2, ".") > 0 {
		hasParent = true
		log.LogDebug(fmt.Sprintf("Attempting DNS TXT lookup for parent domain %s", TXT_PREFIX+lookup2))

		records, err = net.LookupTXT(TXT_PREFIX + lookup2)
		if err == nil && len(records) > 0 {
			if ca, validateErr := validateAndSelectCA(records, TXT_PREFIX+lookup2); validateErr == nil {
				log.LogInfo(fmt.Sprintf("Determined CA: %s (via DNS TXT)", ca))
				log.LogDebug(fmt.Sprintf("Found CA via DNS TXT record at %s: %s", TXT_PREFIX+lookup2, ca))
				caCache.Set(host, ca, time.Duration(CACHE_DURATION))
				return ca, nil
			} else {
				// Cache the error for a shorter duration
				caCache.Set(host, "", time.Duration(CACHE_DURATION_NEG))
				return "", validateErr
			}
		} else if err != nil {
			log.LogDebug(fmt.Sprintf("DNS TXT lookup failed for %s: %v", TXT_PREFIX+lookup2, err))
		}
	}

	// Phase 2: HTTPS Endpoint Discovery
	log.LogDebug("DNS TXT lookups failed, attempting HTTPS endpoint discovery")

	// Try HTTPS probe on full hostname
	if ca, err := probeHTTPSEndpoint(lookup1); err == nil {
		log.LogInfo(fmt.Sprintf("Determined CA: %s (via HTTPS probe)", ca))
		log.LogDebug(fmt.Sprintf("Found CA via HTTPS probe at %s: %s", lookup1, ca))
		caCache.Set(host, ca, time.Duration(CACHE_DURATION))
		return ca, nil
	} else {
		log.LogDebug(fmt.Sprintf("HTTPS probe failed for %s: %v", lookup1, err))
	}

	// Try HTTPS probe on parent domain (if exists)
	if hasParent {
		if ca, err := probeHTTPSEndpoint(lookup2); err == nil {
			log.LogInfo(fmt.Sprintf("Determined CA: %s (via HTTPS probe)", ca))
			log.LogDebug(fmt.Sprintf("Found CA via HTTPS probe at %s: %s", lookup2, ca))
			caCache.Set(host, ca, time.Duration(CACHE_DURATION))
			return ca, nil
		} else {
			log.LogDebug(fmt.Sprintf("HTTPS probe failed for %s: %v", lookup2, err))
		}
	}

	// All discovery methods failed
	caCache.Set(host, "", time.Duration(CACHE_DURATION_NEG))
	if hasParent {
		return "", fmt.Errorf("CA not found via DNS TXT records (%s, %s) or HTTPS probes (%s, %s)",
			TXT_PREFIX+lookup1, TXT_PREFIX+lookup2, lookup1, lookup2)
	}
	return "", fmt.Errorf("CA not found via DNS TXT record (%s) or HTTPS probe (%s)",
		TXT_PREFIX+lookup1, lookup1)
}

// validateAndSelectCA validates TXT records and selects the first valid CA URL.
// It logs warnings if multiple records exist or if URLs are invalid.
func validateAndSelectCA(records []string, lookupName string) (string, error) {
	if len(records) == 0 {
		return "", errors.New("no TXT records found")
	}

	// Warn if multiple records exist
	if len(records) > 1 {
		log.LogWarn(fmt.Sprintf("Multiple TXT records found for %s (using first): %v", lookupName, records))
	}

	// Validate the first record
	caURL := strings.TrimSpace(records[0])
	if caURL == "" {
		return "", fmt.Errorf("TXT record for %s is empty", lookupName)
	}

	// Parse and validate URL
	parsedURL, err := url.Parse(caURL)
	if err != nil {
		return "", fmt.Errorf("invalid URL in TXT record for %s: %w", lookupName, err)
	}

	// Ensure scheme is http or https
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return "", fmt.Errorf("TXT record for %s must contain http:// or https:// URL, got: %s", lookupName, caURL)
	}

	// Ensure host is present
	if parsedURL.Host == "" {
		return "", fmt.Errorf("TXT record for %s contains URL without host: %s", lookupName, caURL)
	}

	return caURL, nil
}

// probeHTTPSEndpoint attempts to discover an oinit-ca server by probing the
// /oinit/ endpoint over HTTPS on port 443. Returns the base URL if successful.
func probeHTTPSEndpoint(hostname string) (string, error) {
	// Construct the full probe URL
	baseURL := fmt.Sprintf("https://%s:%s", hostname, HTTPS_PORT)
	probeURL := baseURL + HTTPS_ENDPOINT

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: HTTPS_TIMEOUT,
		// Don't follow redirects - we want to know if the exact endpoint exists
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Make GET request
	resp, err := client.Get(probeURL)
	if err != nil {
		return "", fmt.Errorf("HTTPS request failed: %w", err)
	}
	defer resp.Body.Close()

	// Check HTTP status code
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	// Read response body (with size limit)
	limitedReader := io.LimitReader(resp.Body, HTTPS_MAX_BODY_SIZE)
	body, err := io.ReadAll(limitedReader)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	// Try to parse as JSON to verify it's an oinit-ca response
	var response map[string]interface{}
	if err := json.Unmarshal(body, &response); err != nil {
		return "", fmt.Errorf("response is not valid JSON: %w", err)
	}

	// Check if response contains expected fields (version or title indicating oinit-ca)
	if version, hasVersion := response["version"]; hasVersion && version != "" {
		log.LogDebug(fmt.Sprintf("Detected oinit-ca at %s (version: %v)", baseURL, version))
		return baseURL, nil
	}

	if title, hasTitle := response["title"]; hasTitle {
		if titleStr, ok := title.(string); ok && strings.Contains(titleStr, "oinit") {
			log.LogDebug(fmt.Sprintf("Detected oinit-ca at %s (title: %s)", baseURL, titleStr))
			return baseURL, nil
		}
	}

	return "", fmt.Errorf("response does not appear to be from oinit-ca: %s", string(body))
}
