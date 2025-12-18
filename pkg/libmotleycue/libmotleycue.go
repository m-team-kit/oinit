// Package libmotleycue provides an API client for select calls of motley_cue
// v0.5.3
package libmotleycue

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
)

const (
	ERR_REQUEST              = "http request failed"
	ERR_RESPONSE_BODY        = "cannot parse response body"
	ERR_UNEXPECTED_ERROR     = "server returned error code but no description"
	ERR_SERVER_RESPONSE      = "server responded: "
	ERR_SERVER_RESPONSE_CODE = "server responded with code: %d"
)

type ApiResponseDetail struct {
	Detail string `json:"detail"`
}

type FlaatErrorDetail struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

type LoginInfo struct {
	Description string `json:"description"`
	LoginHelp   string `json:"login_help"`
	SSHHost     string `json:"ssh_host"`
}

type OpInfo struct {
	Scopes []string `json:"scopes"`
}

type Credentials struct {
	CommandLine string `json:"commandline"`
	Description string `json:"description"`
	LoginHelp   string `json:"login_help"`
	SSHHost     string `json:"ssh_host"`
	SSHUser     string `json:"ssh_user"`
}

type ApiResponseInfo struct {
	LoginInfo    LoginInfo         `json:"login_info"`
	SupportedOPs []string          `json:"supported_OPs"`
	OpsInfo      map[string]OpInfo `json:"ops_info"`
}

type UserStatusState string

const (
	// See https://git.scc.kit.edu/feudal/feudalAdapterLdf/-/blob/master/states.md
	StateDeployed    UserStatusState = "deployed"
	StateNotDeployed UserStatusState = "not_deployed"
	StatePending     UserStatusState = "pending"
	StateRejected    UserStatusState = "rejected"
	StateSuspended   UserStatusState = "suspended"
	StateLimited     UserStatusState = "limited"
	StateUndefined   UserStatusState = "undefined"
)

// Also called "FeudalResponse" in API docs
type ApiResponseUserStatus struct {
	State       UserStatusState `json:"state"`
	Message     string          `json:"message"`
	Credentials Credentials     `json:"credentials"`
}

type Client struct {
	addr string
}

// parseError tries to unmarshal the given response body into
// ApiResponseDetail and returns the enclosed error message as a new error. If
// reading from responseBody or unmarshalling fails, this function return a
// custom error messages.
func parseError(responseBody io.ReadCloser) error {
	// Read the raw body first for logging
	body, err := io.ReadAll(responseBody)
	if err != nil {
		log.Printf("[libmotleycue] Failed to read response body: %s", err)
		return errors.New(ERR_RESPONSE_BODY)
	}

	var response ApiResponseDetail
	if json.Unmarshal(body, &response) != nil {
		log.Printf("[libmotleycue] Failed to parse error response as JSON")
		return errors.New(ERR_RESPONSE_BODY)
	}

	// Make sure the .Detail field was filled after unmarshalling the JSON data.
	if response.Detail == "" {
		// log.Printf("[libmotleycue] No detail field in error response, trying flaat format")
		var flaatResponse FlaatErrorDetail
		if json.Unmarshal(body, &flaatResponse) == nil {
			// Successfully parsed flaat error format
			log.Printf("[libmotleycue] Parsed flaat error: '%s' - '%s'", flaatResponse.Error, flaatResponse.ErrorDescription)
			if flaatResponse.ErrorDescription != "" {
				// Use the more descriptive error_description if available
				return errors.New(fmt.Sprintf("Error: %s - %s", flaatResponse.Error, flaatResponse.ErrorDescription))
			} else if flaatResponse.Error != "" {
				// Fall back to the error field
				return errors.New(flaatResponse.Error)
			}
		}

		// Log the full response for debugging
		log.Printf("[libmotleycue] Full error response: %s", string(body))

		// If we can't parse either format, use default error
		response.Detail = ERR_UNEXPECTED_ERROR
	}

	log.Printf("[libmotleycue] Parsed error detail: %s", response.Detail)
	return errors.New(response.Detail)
}

// parseResponse tries to unmarshal the given response body into a given struct.
// An error is returned for reader or unmarshalling errors.
func parseResponse(responseBody io.ReadCloser, into interface{}) error {
	if body, err := io.ReadAll(responseBody); err != nil ||
		json.Unmarshal(body, into) != nil {
		return errors.New(ERR_RESPONSE_BODY)
	}

	return nil
}

// NewClient creates a new API client. addr is the server address (and port)
// including the protocol, such as http://example.com:8080
func NewClient(addr string) Client {
	addr, _ = strings.CutSuffix(addr, "/")

	return Client{
		addr: addr,
	}
}

// GetInfo calls GET /info.
//
// Retrieve service-specific information:
//
//   - login info
//   - supported OPs
//   - OP info
func (c Client) GetInfo() (ApiResponseInfo, error) {
	var response ApiResponseInfo

	res, err := http.Get(c.addr + "/info")
	if err != nil {
		return response, errors.New(ERR_REQUEST)
	}

	defer res.Body.Close()

	switch res.StatusCode {
	case http.StatusOK:
		return response, parseResponse(res.Body, &response)
	default:
		return response, fmt.Errorf(ERR_SERVER_RESPONSE_CODE, res.StatusCode)
	}
}

// getUser is the implementation of both GET /user/get_status and GET
// /user/deploy, as their request parameters and response are identical.
func (c Client) getUser(path string, token string) (ApiResponseUserStatus, error) {
	var response ApiResponseUserStatus

	req, err := http.NewRequest(http.MethodGet, c.addr+path, nil)
	if err != nil {
		return response, errors.New(ERR_REQUEST)
	}

	req.Header.Set("Authorization", "Bearer "+token)

	client := http.Client{}
	res, err := client.Do(req)
	if err != nil {
		return response, errors.New(ERR_REQUEST)
	}

	defer res.Body.Close()

	log.Printf("[libmotleycue] %s %s returned status: %d", req.Method, req.URL.Path, res.StatusCode)

	switch res.StatusCode {
	case http.StatusOK:
		return response, parseResponse(res.Body, &response)
	case http.StatusUnauthorized:
		log.Printf("[libmotleycue] Unauthorized (401) - token may be invalid or expired")
		return response, parseError(res.Body)
	case http.StatusForbidden:
		log.Printf("[libmotleycue] Forbidden (403) - user may be suspended or access denied")
		return response, parseError(res.Body)
	case http.StatusNotFound:
		log.Printf("[libmotleycue] Not Found (404) - user may not exist")
		return response, parseError(res.Body)
	case http.StatusUnprocessableEntity:
		log.Printf("[libmotleycue] Unprocessable Entity (422) - request format issue")
		// In this case, the response body has a different structure and cannot
		// be parsed easily into a ApiResponseDetail struct, therefore return
		// custom error.
		return response, fmt.Errorf(ERR_SERVER_RESPONSE_CODE, res.StatusCode)
	default:
		log.Printf("[libmotleycue] Unexpected status code: %d", res.StatusCode)
		return response, fmt.Errorf(ERR_SERVER_RESPONSE_CODE, res.StatusCode)
	}
}

// GetUserStatus calls GET /user/status.
//
// Get information about your local account:
//
//   - state: one of the supported states, such as deployed, not_deployed, suspended.
//   - message: could contain additional information, such as the local username
//
// Requires an authorized user.
func (c Client) GetUserStatus(token string) (ApiResponseUserStatus, error) {
	return c.getUser("/user/get_status", token)
}

// GetUserDeploy calls GET /user/deploy.
//
// Provision a local account.
// Requires an authorized user.
func (c Client) GetUserDeploy(token string) (ApiResponseUserStatus, error) {
	return c.getUser("/user/deploy", token)
}
