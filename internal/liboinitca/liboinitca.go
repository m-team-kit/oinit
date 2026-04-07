package liboinitca

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/lbrocke/oinit/internal/api"
)

const (
	ERR_REQUEST              = "http request failed"
	ERR_RESPONSE_BODY        = "cannot parse response body"
	ERR_SERVER_RESPONSE      = "server responded: "
	ERR_SERVER_RESPONSE_CODE = "server responded with unexpected code: %d"

	API_V1 = "/oinit/api/v1"
)

type Client struct {
	addrs []string
}

// parseError tries to unmarshal the given response body into
// ApiResponseError and returns the enclosed error message as a new error. If
// reading from responseBody or unmarshalling fails, this function return a
// custom error messages.
func parseError(responseBody io.ReadCloser) error {
	var response api.ApiResponseError

	if parseResponse(responseBody, &response) != nil {
		return errors.New(ERR_RESPONSE_BODY)
	}

	return errors.New(response.Error)
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

	if strings.Contains(addr, "://") {
		return Client{
			addrs: []string{addr},
		}
	}

	return Client{
		addrs: []string{"https://" + addr, "http://" + addr},
	}
}

// Return the CA public key and supported OpenID Connect providers.
func (c Client) GetHost(host string) (api.ApiResponseHost, error) {
	var response api.ApiResponseHost

	for _, base := range c.addrs {
		res, err := http.Get(fmt.Sprintf("%s%s/%s", base, API_V1, url.PathEscape(host)))
		if err != nil {
			continue
		}

		// ensure body is closed before next iteration/return
		switch res.StatusCode {
		case http.StatusOK:
			err = parseResponse(res.Body, &response)
			res.Body.Close()
			return response, err
		case http.StatusBadRequest:
			fallthrough
		case http.StatusNotFound:
			fallthrough
		case http.StatusInternalServerError:
			fallthrough
		case http.StatusBadGateway:
			err = parseError(res.Body)
			res.Body.Close()
			return response, err
		default:
			res.Body.Close()
			return response, fmt.Errorf(ERR_SERVER_RESPONSE_CODE, res.StatusCode)
		}
	}

	return response, errors.New(ERR_REQUEST)
}

// Generate and return a new SSH certificate using the given access token.
// The issuer parameter is optional and provides the OIDC issuer URL for
// non-JWT tokens where the issuer cannot be extracted from the token itself.
func (c Client) PostHostCertificate(host, pubkey, token, issuer string) (api.ApiResponseCertificate, error) {
	var response api.ApiResponseCertificate

	reqBody, err := json.Marshal(api.FormHostCertificate{
		Publickey: pubkey,
		Token:     token,
		Issuer:    issuer,
	})
	if err != nil {
		return response, err
	}

	for _, base := range c.addrs {
		res, err := http.Post(fmt.Sprintf("%s%s/%s/certificate", base, API_V1, url.PathEscape(host)), "application/json", bytes.NewReader(reqBody))
		if err != nil {
			continue
		}

		switch res.StatusCode {
		case http.StatusCreated:
			err = parseResponse(res.Body, &response)
			res.Body.Close()
			return response, err
		case http.StatusBadRequest:
			fallthrough
		case http.StatusUnauthorized:
			fallthrough
		case http.StatusNotFound:
			fallthrough
		case http.StatusInternalServerError:
			fallthrough
		case http.StatusBadGateway:
			err = parseError(res.Body)
			res.Body.Close()
			return response, err
		default:
			res.Body.Close()
			return response, fmt.Errorf(ERR_SERVER_RESPONSE_CODE, res.StatusCode)
		}
	}

	return response, errors.New(ERR_REQUEST)
}
