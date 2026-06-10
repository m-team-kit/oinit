package api

import (
	"crypto/rand"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/lbrocke/oinit/internal/config"
	oidcutil "github.com/lbrocke/oinit/internal/oidc"
	"github.com/lbrocke/oinit/internal/util"
	"github.com/lbrocke/oinit/pkg/libmotleycue"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/ssh"
	"golang.org/x/exp/slices"
)

const (
	API_VERSION = "1.0.0"

	ERR_BAD_BODY       = "Request body is malformed."
	ERR_UNKNOWN_HOST   = "Unknown host."
	ERR_GATEWAY_DOWN   = "motley_cue is not reachable."
	ERR_UNAUTHORIZED   = "User is not authorized or suspended."
	ERR_INTERNAL_ERROR = "Internal server error."
	ERR_RATE_LIMITED   = "Too many requests, please slow down."
)

type ApiResponseError struct {
	Error string `json:"error"`
}

type ApiResponseIndex struct {
	Version string `json:"version"`
}

type ApiResponseHost struct {
	PublicKey string     `json:"publickey"`
	Providers []Provider `json:"providers"`
}

type ApiResponseCertificate struct {
	Certificate string `json:"certificate"`
}

type Provider struct {
	URL    string   `json:"url"`
	Scopes []string `json:"scopes"`
}

type UriHost struct {
	Host string `uri:"host" binding:"required"`
}

type FormHostCertificate struct {
	Publickey string `json:"publickey" binding:"required"`
	Token     string `json:"token" binding:"required"`
	Issuer    string `json:"issuer"`
}

func Error(c *gin.Context, code int, msg string) {
	c.JSON(code, ApiResponseError{
		Error: msg,
	})
}

// debugf logs only when OINIT_DEBUG is set. It is used for verbose,
// step-by-step identity resolution traces (issuer/subject from each source)
// that are redundant with the single audit line emitted per issued
// certificate. Gating them keeps personal data (sub/iss) out of normal logs.
func debugf(format string, args ...interface{}) {
	if os.Getenv("OINIT_DEBUG") != "" {
		log.Printf(format, args...)
	}
}

type customLog struct {
}

// Custom log format that imitates gin's output
func (writer customLog) Write(bytes []byte) (int, error) {
	return fmt.Print("[API] " + time.Now().Format("2006/01/02 - 15:04:05") + " " + string(bytes))
}

var cache = util.NewTimedCache[string, []Provider]()

// resolveProviders returns the OpenID Connect providers advertised by the
// host's motley_cue instance, using a short-lived cache. Only issuers that are
// both listed in SupportedOPs and have scope info are returned.
func resolveProviders(info config.HostInfo) ([]Provider, error) {
	if providers, ok := cache.Get(info.URL); ok {
		return providers, nil
	}

	hostInfo, err := libmotleycue.NewClient(info.URL).GetInfo()
	if err != nil {
		return nil, err
	}

	var providers []Provider
	// Iterate OpsInfo instead of SupportedOPs to only add hosts for which
	// scopes are defined. Validate that issuer is listed in SupportedOPs
	// however.
	for issuer, opInfo := range hostInfo.OpsInfo {
		if slices.Contains(hostInfo.SupportedOPs, issuer) {
			providers = append(providers, Provider{
				URL:    issuer,
				Scopes: opInfo.Scopes,
			})
		}
	}

	cache.Set(info.URL, providers, time.Duration(info.CacheDuration))
	return providers, nil
}

// isSupportedIssuer reports whether the given issuer URL is one advertised by
// the host's motley_cue instance. This gates outbound requests made with an
// issuer that may have been supplied by the client (e.g. for opaque tokens),
// preventing the CA from being used as an SSRF vector.
func isSupportedIssuer(info config.HostInfo, issuer string) bool {
	if issuer == "" {
		return false
	}

	providers, err := resolveProviders(info)
	if err != nil {
		return false
	}

	for _, p := range providers {
		if p.URL == issuer {
			return true
		}
	}

	return false
}

// GetIndex is the handler for GET /
//
//	@Summary		Get API version
//	@Description	Return the running API version.
//	@Produce		json
//	@Success		200	{object}	ApiResponseIndex
//	@Router			/ [get]
func GetIndex(c *gin.Context) {
	c.JSON(http.StatusOK, ApiResponseIndex{
		Version: API_VERSION,
	})
}

// GetHealth is the handler for GET /health
//
//	@Summary		Health check endpoint
//	@Description	Returns health status for Docker Compose health checks
//	@Produce		json
//	@Success		200	{object}	gin.H
//	@Router			/health [get]
func GetHealth(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":  "healthy",
		"service": "oinit-ca",
		"version": API_VERSION,
	})
}

func unknownHostError(h string) string {
	return fmt.Sprintf("Host '%s' is not managed by this CA.", h)
}

// GetOverview is a minimal API overview for root paths.
func GetOverview(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"title":   "oinit CA API",
		"version": API_VERSION,
		"endpoints": []string{
			"/oinit/api/v1/",
			"/oinit/api/v1/{host}",
			"/oinit/api/v1/{host}/certificate",
			"/oinit/api/docs/",
		},
	})
}

// GetHost is the handler for GET /:host
//
//	@Summary		Get host information
//	@Description	Return the CA public key and supported OpenID Connect providers with their required scopes.
//	@Produce		json
//	@Param			host	path		string	true	"Host"	example("example.com")
//	@Success		200		{object}	ApiResponseHost
//	@Failure		400		{object}	ApiResponseError
//	@Failure		404		{object}	ApiResponseError
//	@Failure		500		{object}	ApiResponseError
//	@Failure		502		{object}	ApiResponseError
//	@Router			/{host} [get]
func GetHost(c *gin.Context) {
	log.SetFlags(0)
	log.SetOutput(new(customLog))
	var host UriHost

	if c.ShouldBindUri(&host) != nil {
		Error(c, http.StatusBadRequest, ERR_BAD_BODY)
		return
	}

	host.Host = strings.ToLower(host.Host)

	conf, ok := c.MustGet("config").(config.Config)
	if !ok {
		Error(c, http.StatusInternalServerError, ERR_INTERNAL_ERROR)
		return
	}

	info, err := conf.GetInfo(host.Host)
	if err != nil {
		Error(c, http.StatusNotFound, unknownHostError(host.Host))
		return
	}

	providers, err := resolveProviders(info)
	if err != nil {
		log.Printf("Error connecting to motley_cue: %s", err)
		Error(c, http.StatusBadGateway, ERR_GATEWAY_DOWN)
		return
	}

	c.JSON(http.StatusOK, ApiResponseHost{
		PublicKey: strings.TrimSuffix(string(ssh.MarshalAuthorizedKey(info.HostCAPublicKey)), "\n"),
		Providers: providers,
	})
}

// PostHostCertificate is the handler for POST /:host/certificate
//
//	@Summary		Generate SSH certificate
//	@Description	Generate and return a new SSH certificate using the given public key and access token.
//	@Accept			json
//	@Produce		json
//	@Param			host	path		string				true	"Host"	example("example.com")
//	@Param			body	body		FormHostCertificate	true	"Public key and access token"
//	@Success		201		{object}	ApiResponseCertificate
//	@Failure		400		{object}	ApiResponseError
//	@Failure		401		{object}	ApiResponseError
//	@Failure		404		{object}	ApiResponseError
//	@Failure		500		{object}	ApiResponseError
//	@Failure		502		{object}	ApiResponseError
//	@Router			/{host}/certificate [post]
func PostHostCertificate(c *gin.Context) {
	log.SetFlags(0)
	log.SetOutput(new(customLog))

	var host UriHost
	var body FormHostCertificate

	if c.ShouldBindUri(&host) != nil || c.ShouldBindJSON(&body) != nil {
		Error(c, http.StatusBadRequest, ERR_BAD_BODY)
		return
	}

	host.Host = strings.ToLower(host.Host)

	conf, ok := c.MustGet("config").(config.Config)
	if !ok {
		Error(c, http.StatusInternalServerError, ERR_INTERNAL_ERROR)
		return
	}

	info, err := conf.GetInfo(host.Host)
	if err != nil {
		Error(c, http.StatusNotFound, unknownHostError(host.Host))
		return
	}

	pubkey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(body.Publickey))
	if err != nil {
		Error(c, http.StatusBadRequest, ERR_BAD_BODY)
		return
	}

	// Call motley_cue to validate the token. If provisioning is enabled
	// (default), use /user/deploy to also provision a local account.
	// Otherwise, use /user/get_status for validation only.
	mcClient := libmotleycue.NewClient(info.URL)
	var status libmotleycue.ApiResponseUserStatus
	if info.ProvisionUser {
		status, err = mcClient.GetUserDeploy(body.Token)
	} else {
		status, err = mcClient.GetUserStatus(body.Token)
	}
	if err != nil {
		// HTTP error or network issue - pass through the specific error from libmotleycue
		log.Printf("motley_cue error: %s", err)
		Error(c, http.StatusUnauthorized, err.Error())
		return
	}

	// Handle different user states appropriately
	switch status.State {
	case libmotleycue.StateDeployed:
		// Success case - continue with certificate generation
	case libmotleycue.StateSuspended:
		log.Printf("User suspended: %s", status.Message)
		Error(c, http.StatusForbidden, "User account is suspended: "+status.Message)
		return
	case libmotleycue.StateRejected:
		log.Printf("User rejected: %s", status.Message)
		Error(c, http.StatusForbidden, "User account is rejected: "+status.Message)
		return
	case libmotleycue.StatePending:
		log.Printf("User pending: %s", status.Message)
		Error(c, http.StatusAccepted, "User account is pending approval: "+status.Message)
		return
	case libmotleycue.StateNotDeployed:
		log.Printf("User not deployed: %s", status.Message)
		Error(c, http.StatusForbidden, "User account is not deployed: "+status.Message)
		return
	case libmotleycue.StateLimited:
		log.Printf("User limited: %s", status.Message)
		Error(c, http.StatusForbidden, "User account has limited access: "+status.Message)
		return
	default:
		log.Printf("Unknown user state '%s': %s", status.State, status.Message)
		Error(c, http.StatusForbidden, "User account state is undefined: "+status.Message)
		return
	}

	certDuration := info.CertDuration
	// Parse JWT without verifying it, as the signer key is unknown to the CA.
	// motley_cue will verify the token instead.
	token, _, err := new(jwt.Parser).ParseUnverified(body.Token, jwt.MapClaims{})

	// Extract issuer, subject, and username - prefer motley_cue response, fallback to JWT
	var issuer string = "unknown"
	var subject string = "unknown"
	var username string = status.Credentials.SSHUser // default from credentials

	// First: the username
	// When provisioning is disabled, use the configured default user
	if !info.ProvisionUser {
		username = info.DefaultUser
	}
	if info.ProvisionUser && status.Username != "" {
		username = status.Username
	}

	// Second: use various ways to find sub and iss
	// 1: use JWT claims to find sub and iss.
	if err == nil && (issuer == "unknown" || subject == "unknown") {
		if claims, ok := token.Claims.(jwt.MapClaims); ok {
			if issuer == "unknown" {
				if iss, exists := claims["iss"]; exists {
					if issStr, ok := iss.(string); ok {
						issuer = issStr
						debugf("Retrieved issuer from JWT: %s", issuer)
					}
				}
			}
			if subject == "unknown" {
				if sub, exists := claims["sub"]; exists {
					if subStr, ok := sub.(string); ok {
						subject = subStr
						debugf("Retrieved subject from JWT: %s", subject)
					}
				}
			}
		}
	}

	// 2: use motley_cue response fields if available
	if issuer == "unknown" && status.Iss != "" {
		issuer = status.Iss
		debugf("Retrieved issuer from motley_cue: %s", issuer)
	}
	if subject == "unknown" && status.Sub != "" {
		subject = status.Sub
		debugf("Retrieved subject from motley_cue: %s", subject)
	}

	// 3: use client-provided issuer (for non-JWT/opaque tokens). Only accept
	// it if motley_cue advertises it as a supported provider, so a client
	// cannot point the CA at an arbitrary issuer URL.
	if issuer == "unknown" && body.Issuer != "" {
		if isSupportedIssuer(info, body.Issuer) {
			issuer = body.Issuer
			debugf("Retrieved issuer from client request: %s", issuer)
		} else {
			log.Printf("Ignoring unsupported client-provided issuer: %s", body.Issuer)
		}
	}

	// 4: if subject is still unknown but we have an issuer, try the
	// userinfo endpoint to obtain the subject claim. This is needed
	// for opaque (non-JWT) access tokens. The userinfo lookup performs an
	// outbound HTTP request to the issuer, so only do it for issuers that
	// motley_cue advertises (defence-in-depth against SSRF, even though a
	// JWT-derived issuer is already trustworthy).
	if subject == "unknown" && issuer != "unknown" && isSupportedIssuer(info, issuer) {
		if sub, err := oidcutil.LookupSubject(issuer, body.Token); err == nil {
			subject = sub
			debugf("Retrieved subject from userinfo endpoint: %s", subject)
		} else {
			log.Printf("Userinfo lookup failed: %s", err)
		}
	}

	log.Printf("Final values - issuer: %s, subject: %s, username: %s", issuer, subject, username)
	if err == nil { // we had a JWT token, get the certDuration from token lifetime
		if certDuration <= 0 {
			if exp, err := token.Claims.GetExpirationTime(); err == nil {
				certDuration = int(time.Until(exp.Time).Seconds())
			}
		}
	} else {
		certDuration = info.CertValidityFallback
		log.Printf("Using fallback certDuration: %ds", certDuration)
	}

	// Resolve principals from config template, replacing $provisioned-user.
	// The "oinit" service user is always included as a certificate principal
	// but is not part of $cert-principals (used in force-command).
	var configPrincipals []string
	for _, p := range strings.Fields(info.CertPrincipals) {
		resolved := strings.ReplaceAll(p, "$provisioned-user", username)
		if resolved != "oinit" {
			configPrincipals = append(configPrincipals, resolved)
		}
	}
	principals := append([]string{"oinit"}, configPrincipals...)

	// Resolve force-command from config template.
	// $cert-principals expands to the configured principals (without "oinit").
	forceCommand := strings.ReplaceAll(info.ForceCommand, "$cert-principals", strings.Join(configPrincipals, " "))
	forceCommand = strings.ReplaceAll(forceCommand, "$provisioned-user", username)

	cert := generateUserCertificate(host.Host, pubkey, username, subject, issuer, uint64(certDuration), principals, forceCommand)

	signer, err := ssh.NewSignerFromKey(info.UserCAPrivateKey)
	if err != nil || cert.SignCert(rand.Reader, signer) != nil {
		Error(c, http.StatusUnauthorized, ERR_INTERNAL_ERROR)
		return
	}

	log.Printf("Issued certificate '%s' valid until '%s'", ssh.FingerprintSHA256(cert.Key), time.Unix(int64(cert.ValidBefore-1), 0))

	c.JSON(http.StatusCreated, ApiResponseCertificate{
		Certificate: strings.TrimSuffix(string(ssh.MarshalAuthorizedKey(&cert)), "\n"),
	})
}
