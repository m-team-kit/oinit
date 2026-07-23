package api

import (
	"crypto/rand"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
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

// usernameRe matches a plain lowercase POSIX-style local username. The
// resolved username is embedded into the certificate principals and the
// force-command ("oinit-switch <username>"); restricting it to this set
// ensures it cannot contain whitespace or other characters that would change
// how oinit-shell splits the forced command or which account oinit-switch
// selects. Uppercase and Samba machine-account trailing "$" are intentionally
// disallowed.
var usernameRe = regexp.MustCompile(`^[a-z_][a-z0-9_-]*$`)

// isValidUsername reports whether name is a safe local username to embed into a
// certificate's principals and force-command.
func isValidUsername(name string) bool {
	return len(name) > 0 && len(name) <= 32 && usernameRe.MatchString(name)
}

// sanitizeIdentity makes an issuer or subject string safe to embed in a
// certificate KeyId and in log lines. It removes control characters (which
// include the newlines an attacker could use to forge log entries) and caps the
// length. These values may originate from a token whose signature the CA cannot
// itself verify, so they are treated as untrusted text.
func sanitizeIdentity(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	if len(s) > 256 {
		s = s[:256]
	}
	return s
}

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

	// Parse the token without verifying, only to discover the claimed issuer:
	// the CA needs the issuer to know which JWKS to fetch. Nothing from an
	// unverified token is trusted at this point.
	unverified, _, parseErr := new(jwt.Parser).ParseUnverified(body.Token, jwt.MapClaims{})
	isJWT := parseErr == nil

	var issuer string = "unknown"
	var subject string = "unknown"
	var username string = status.Credentials.SSHUser // default from credentials

	// First: the username.
	// When provisioning is disabled, use the configured default user.
	if !info.ProvisionUser {
		username = info.DefaultUser
	}
	if info.ProvisionUser && status.Username != "" {
		username = status.Username
	}

	// Second: establish issuer and subject.
	//
	// verifiedClaims holds cryptographically verified JWT claims, or nil for an
	// opaque (non-JWT) access token.
	var verifiedClaims jwt.MapClaims

	if isJWT {
		// The token presents as a JWT: verify its signature against the issuing
		// provider's JWKS before trusting any claim. The issuer is read
		// (unverified) from the token only to select the JWKS and must be one
		// motley_cue advertises - both to avoid turning the CA into an SSRF
		// vector and because keys are only trustworthy from a known provider.
		uClaims, _ := unverified.Claims.(jwt.MapClaims)
		issFromToken, _ := uClaims["iss"].(string)

		if !isSupportedIssuer(info, issFromToken) {
			log.Printf("Refusing JWT with unsupported or missing issuer: %q", issFromToken)
			Error(c, http.StatusUnauthorized, ERR_UNAUTHORIZED)
			return
		}

		claims, verr := oidcutil.VerifyToken(issFromToken, body.Token)
		if verr != nil {
			if errors.Is(verr, oidcutil.ErrTokenInvalid) {
				log.Printf("JWT verification failed for issuer %q: %s", issFromToken, verr)
				Error(c, http.StatusUnauthorized, ERR_UNAUTHORIZED)
			} else {
				log.Printf("Could not verify JWT with issuer %q: %s", issFromToken, verr)
				Error(c, http.StatusBadGateway, ERR_GATEWAY_DOWN)
			}
			return
		}

		verifiedClaims = claims
		issuer = issFromToken
		if sub, ok := claims["sub"].(string); ok {
			subject = sub
			debugf("Retrieved subject from verified JWT: %s", subject)
		}
	}

	// For opaque tokens (and to fill any gaps), fall back to motley_cue response
	// fields if available.
	if issuer == "unknown" && status.Iss != "" {
		issuer = status.Iss
		debugf("Retrieved issuer from motley_cue: %s", issuer)
	}
	if subject == "unknown" && status.Sub != "" {
		subject = status.Sub
		debugf("Retrieved subject from motley_cue: %s", subject)
	}

	// Use the client-provided issuer (for opaque tokens). Only accept it if
	// motley_cue advertises it as a supported provider, so a client cannot point
	// the CA at an arbitrary issuer URL.
	if issuer == "unknown" && body.Issuer != "" {
		if isSupportedIssuer(info, body.Issuer) {
			issuer = body.Issuer
			debugf("Retrieved issuer from client request: %s", issuer)
		} else {
			log.Printf("Ignoring unsupported client-provided issuer: %s", body.Issuer)
		}
	}

	// If the subject is still unknown but we have a supported issuer, query the
	// userinfo endpoint to obtain it (needed for opaque access tokens). The
	// lookup performs an outbound request to the issuer, gated to advertised
	// providers as defence-in-depth against SSRF.
	if subject == "unknown" && issuer != "unknown" && isSupportedIssuer(info, issuer) {
		if sub, err := oidcutil.LookupSubject(issuer, body.Token); err == nil {
			subject = sub
			debugf("Retrieved subject from userinfo endpoint: %s", subject)
		} else {
			log.Printf("Userinfo lookup failed: %s", err)
		}
	}

	// issuer and subject are embedded into the certificate KeyId and written to
	// the log; sanitise them so a value carrying control characters or newlines
	// cannot forge log entries or corrupt the certificate identity.
	issuer = sanitizeIdentity(issuer)
	subject = sanitizeIdentity(subject)

	log.Printf("Final values - issuer: %s, subject: %s, username: %s", issuer, subject, username)

	if verifiedClaims != nil { // verified JWT: derive cert lifetime from its expiry
		if certDuration <= 0 {
			if exp, err := verifiedClaims.GetExpirationTime(); err == nil && exp != nil {
				certDuration = int(time.Until(exp.Time).Seconds())
			}
		}
	} else {
		certDuration = info.CertValidityFallback
		log.Printf("Using fallback certDuration: %ds", certDuration)
	}

	// Guard against a non-positive duration. uint64(negative) would wrap to an
	// enormous value and yield a practically non-expiring certificate, so
	// refuse rather than issue something unbounded.
	if certDuration <= 0 {
		log.Printf("Refusing to issue certificate with non-positive duration: %ds", certDuration)
		Error(c, http.StatusInternalServerError, ERR_INTERNAL_ERROR)
		return
	}

	// The resolved username is embedded into the certificate principals and the
	// force-command. Reject anything that is not a plain POSIX username so it
	// cannot alter how the forced command is parsed or which account
	// oinit-switch ultimately selects.
	if !isValidUsername(username) {
		log.Printf("Refusing to issue certificate for invalid username: %q", username)
		Error(c, http.StatusInternalServerError, ERR_INTERNAL_ERROR)
		return
	}

	// Issuing a certificate for the root account is a privileged, dangerous
	// operation and is therefore gated behind the per-host-group allow-root
	// option (default: deny). The server-side oinit-switch and PAM must also be
	// configured to permit the oinit -> root switch for the login to succeed.
	if username == "root" && !info.AllowRoot {
		log.Printf("Refusing to issue root certificate: allow-root is not enabled for host %q", host.Host)
		Error(c, http.StatusForbidden, ERR_UNAUTHORIZED)
		return
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
