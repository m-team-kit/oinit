package api

import (
	"crypto/rand"
	"net/http"
	"oinit-ca/config"
	"oinit-ca/libmotleycue"
	"strings"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/ssh"
)

const (
	API_VERSION = "0.1.0"

	ERR_BAD_BODY       = "Request body is malformed."
	ERR_UNKNOWN_HOST   = "Unknown host."
	ERR_GATEWAY_DOWN   = "motley_cue is not reachable."
	ERR_UNAUTHORIZED   = "User is not authorized or suspended."
	ERR_INTERNAL_ERROR = "Internal server error."
)

type ApiResponseError struct {
	Error string `json:"error"`
}

type ApiResponseIndex struct {
	Version string `json:"version"`
}

type ApiResponseHost struct {
	PublicKey string   `json:"publickey"`
	Providers []string `json:"providers"`
}

type ApiResponseCertificate struct {
	Certificate string `json:"certificate"`
}

type UriHost struct {
	Host string `uri:"host" binding:"required"`
}

type FormHostCertificate struct {
	Pubkey string `json:"pubkey" binding:"required"`
	Token  string `json:"token" binding:"required"`
}

func Error(c *gin.Context, code int, msg string) {
	c.JSON(code, ApiResponseError{
		Error: msg,
	})
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

// GetHost is the handler for GET /:host
//
//	@Summary		Get host information
//	@Description	Return the CA public key and supported OpenID Connect providers.
//	@Produce		json
//	@Param			host	path		string	true	"Host"	example("example.com")
//	@Success		200		{object}	ApiResponseHost
//	@Failure		400		{object}	ApiResponseError
//	@Failure		500		{object}	ApiResponseError
//	@Failure		502		{object}	ApiResponseError
//	@Router			/{host} [get]
func GetHost(c *gin.Context) {
	var host UriHost

	if c.ShouldBindUri(&host) != nil {
		Error(c, http.StatusBadRequest, ERR_BAD_BODY)
		return
	}

	conf, ok := c.MustGet("config").(config.Config)
	if !ok {
		Error(c, http.StatusInternalServerError, ERR_INTERNAL_ERROR)
		return
	}

	ca, err := conf.GetMotleyCueURL(host.Host)
	if err != nil {
		Error(c, http.StatusBadRequest, ERR_UNKNOWN_HOST)
		return
	}

	keys, err := conf.GetKeys(host.Host)
	if err != nil {
		// This should not happen, as the non-existence of the given host
		// should have already resulted in an error in the previous call to
		// conf.GetMotleyCueURL()
		Error(c, http.StatusBadRequest, ERR_UNKNOWN_HOST)
		return
	}

	info, err := libmotleycue.NewClient(ca).GetInfo()
	if err != nil {
		Error(c, http.StatusBadGateway, ERR_GATEWAY_DOWN)
		return
	}

	c.JSON(http.StatusOK, ApiResponseHost{
		PublicKey: strings.TrimSuffix(string(ssh.MarshalAuthorizedKey(keys.HostCAPublicKey)), "\n"),
		Providers: info.SupportedOPs,
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
//	@Failure		500		{object}	ApiResponseError
//	@Failure		502		{object}	ApiResponseError
//	@Router			/{host}/certificate [post]
func PostHostCertificate(c *gin.Context) {
	var host UriHost
	var body FormHostCertificate

	if c.ShouldBindUri(&host) != nil || c.ShouldBindJSON(&body) != nil {
		Error(c, http.StatusBadRequest, ERR_BAD_BODY)
		return
	}

	pubkey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(body.Pubkey))
	if err != nil {
		Error(c, http.StatusBadRequest, ERR_BAD_BODY)
		return
	}

	conf, ok := c.MustGet("config").(config.Config)
	if !ok {
		Error(c, http.StatusInternalServerError, ERR_INTERNAL_ERROR)
		return
	}

	ca, err := conf.GetMotleyCueURL(host.Host)
	if err != nil {
		Error(c, http.StatusBadRequest, ERR_UNKNOWN_HOST)
		return
	}

	keys, err := conf.GetKeys(host.Host)
	if err != nil {
		// This should not happen, as the non-existence of the given host
		// should have already resulted in an error in the previous call to
		// conf.GetMotleyCueURL()
		Error(c, http.StatusBadRequest, ERR_UNKNOWN_HOST)
		return
	}

	status, err := libmotleycue.NewClient(ca).GetUserStatus(body.Token)
	if err != nil {
		// Either something went wrong with the HTTP request, or the access
		// token is not valid
		Error(c, http.StatusUnauthorized, ERR_UNAUTHORIZED)
		return
	}

	switch status.State {
	case libmotleycue.StateNotDeployed:
		// User is not yet deployed but still authorized. Deployment is not
		// a task of the CA, it is instead done later on first ssh login.
		break
	case libmotleycue.StateDeployed:
		break
	case libmotleycue.StateSuspended:
		// User is not allowed to login, therefore there is no reason to issue
		// a certificate.
		fallthrough
	default:
		Error(c, http.StatusUnauthorized, ERR_UNAUTHORIZED)
		return
	}

	cert := generateUserCertificate(pubkey, body.Token)

	signer, err := ssh.NewSignerFromKey(keys.UserCAPrivateKey)
	if err != nil || cert.SignCert(rand.Reader, signer) != nil {
		Error(c, http.StatusUnauthorized, ERR_INTERNAL_ERROR)
		return
	}

	// Make sure that certificate is valid and (this *very* is important!) has
	// the force-command option set to the correct (non-empty) value.
	if !validateUserCertificate(cert, keys.UserCAPublicKey) {
		Error(c, http.StatusInternalServerError, ERR_INTERNAL_ERROR)
		return
	}

	c.JSON(http.StatusCreated, ApiResponseCertificate{
		Certificate: strings.TrimSuffix(string(ssh.MarshalAuthorizedKey(&cert)), "\n"),
	})
}
