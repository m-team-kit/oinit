package oidc

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/lbrocke/oinit/internal/util"
)

// JWKS_CACHE_DURATION is how long (in seconds) a fetched JWKS is cached per
// issuer. Signing keys rotate infrequently; a moderate TTL avoids a network
// round-trip on every certificate request without pinning stale keys for long.
const JWKS_CACHE_DURATION = 900 // 15 minutes

// minRSABits is the smallest RSA modulus accepted for a signing key.
const minRSABits = 2048

// allowedAlgs restricts JWT verification to asymmetric signature algorithms.
// alg:none and HMAC (symmetric) are deliberately excluded: accepting HMAC would
// allow an "algorithm confusion" attack where an attacker signs a token with
// the public key as the HMAC secret, and alg:none disables verification
// entirely.
var allowedAlgs = []string{
	"RS256", "RS384", "RS512",
	"PS256", "PS384", "PS512",
	"ES256", "ES384", "ES512",
}

// ErrTokenInvalid indicates the token itself failed verification (bad
// signature, expired, no matching key, disallowed algorithm). It is distinct
// from an infrastructure error (issuer discovery or JWKS fetch failing), so the
// caller can respond 401 vs 5xx appropriately.
var ErrTokenInvalid = errors.New("token failed verification")

// jwksCache maps an issuer URL to its parsed signing keys (keyed by "kid").
var jwksCache = util.NewTimedCache[string, map[string]crypto.PublicKey]()

// VerifyToken cryptographically verifies rawToken as a JWT signed by issuerURL,
// using the signing keys published in that issuer's JWKS (discovered via the
// OpenID Connect .well-known document). On success it returns the verified
// claims; standard claims such as "exp" are validated by the parser.
//
// The caller MUST have already vetted issuerURL (e.g. via a supported-provider
// check): it is used to fetch the discovery document and JWKS over the network.
//
// A token that fails verification yields an error wrapping ErrTokenInvalid;
// discovery/JWKS retrieval failures are returned as plain errors.
func VerifyToken(issuerURL, rawToken string) (jwt.MapClaims, error) {
	keys, err := getJWKS(issuerURL)
	if err != nil {
		return nil, fmt.Errorf("jwks: %w", err)
	}

	return verifyWithKeys(rawToken, keys)
}

// verifyWithKeys verifies rawToken against an already-resolved set of signing
// keys, restricting the accepted signature algorithms to allowedAlgs. It is the
// network-free core of VerifyToken. A verification failure wraps ErrTokenInvalid.
func verifyWithKeys(rawToken string, keys map[string]crypto.PublicKey) (jwt.MapClaims, error) {
	claims := jwt.MapClaims{}
	parser := jwt.NewParser(jwt.WithValidMethods(allowedAlgs))
	if _, err := parser.ParseWithClaims(rawToken, claims, keyfuncFor(keys)); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTokenInvalid, err)
	}

	return claims, nil
}

// keyfuncFor returns a jwt.Keyfunc that selects the verification key by the
// token's "kid" header. If the token carries no "kid" it is only accepted when
// the JWKS holds exactly one key.
func keyfuncFor(keys map[string]crypto.PublicKey) jwt.Keyfunc {
	return func(token *jwt.Token) (interface{}, error) {
		if kid, ok := token.Header["kid"].(string); ok && kid != "" {
			if key, ok := keys[kid]; ok {
				return key, nil
			}
			return nil, fmt.Errorf("no signing key for kid %q", kid)
		}
		if len(keys) == 1 {
			for _, key := range keys {
				return key, nil
			}
		}
		return nil, errors.New("token has no kid and issuer publishes multiple keys")
	}
}

// getJWKS returns the signing keys for issuerURL, fetching and caching them on a
// miss.
func getJWKS(issuerURL string) (map[string]crypto.PublicKey, error) {
	if keys, ok := jwksCache.Get(issuerURL); ok {
		return keys, nil
	}

	cfg, err := fetchDiscovery(issuerURL)
	if err != nil {
		return nil, err
	}
	if cfg.JwksURI == "" {
		return nil, errors.New("discovery document does not contain jwks_uri")
	}
	if err := requireHTTPS(cfg.JwksURI); err != nil {
		return nil, fmt.Errorf("jwks_uri: %w", err)
	}

	keys, err := fetchJWKS(cfg.JwksURI)
	if err != nil {
		return nil, err
	}

	jwksCache.Set(issuerURL, keys, time.Duration(JWKS_CACHE_DURATION))
	return keys, nil
}

// jwk is a single JSON Web Key (only the fields needed to reconstruct RSA and
// EC public keys).
type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	N   string `json:"n"` // RSA modulus
	E   string `json:"e"` // RSA public exponent
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

type jwkSet struct {
	Keys []jwk `json:"keys"`
}

// fetchJWKS retrieves and parses the JWKS at jwksURL into a map of usable public
// keys keyed by "kid".
func fetchJWKS(jwksURL string) (map[string]crypto.PublicKey, error) {
	resp, err := httpClient.Get(jwksURL)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", jwksURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s returned status %d", jwksURL, resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, MAX_RESPONSE_SIZE))
	if err != nil {
		return nil, fmt.Errorf("reading JWKS: %w", err)
	}

	var set jwkSet
	if err := json.Unmarshal(body, &set); err != nil {
		return nil, fmt.Errorf("parsing JWKS: %w", err)
	}

	keys := make(map[string]crypto.PublicKey)
	for _, k := range set.Keys {
		// Skip keys explicitly marked for encryption rather than signing.
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		pub, err := k.publicKey()
		if err != nil {
			// Skip individual unparseable/weak keys rather than failing the
			// whole set; a usable key may still be present.
			continue
		}
		keys[k.Kid] = pub
	}

	if len(keys) == 0 {
		return nil, errors.New("JWKS contains no usable signing keys")
	}
	return keys, nil
}

// publicKey reconstructs a crypto.PublicKey from a JWK. Only RSA and EC keys are
// supported. RSA keys below minRSABits are rejected.
func (k jwk) publicKey() (crypto.PublicKey, error) {
	switch k.Kty {
	case "RSA":
		nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			return nil, fmt.Errorf("invalid RSA modulus: %w", err)
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			return nil, fmt.Errorf("invalid RSA exponent: %w", err)
		}
		if len(eBytes) == 0 || len(eBytes) > 8 {
			return nil, errors.New("invalid RSA exponent length")
		}
		n := new(big.Int).SetBytes(nBytes)
		if n.BitLen() < minRSABits {
			return nil, fmt.Errorf("RSA key too small: %d bits", n.BitLen())
		}
		e := int(new(big.Int).SetBytes(eBytes).Int64())
		if e < 2 {
			return nil, errors.New("invalid RSA exponent")
		}
		return &rsa.PublicKey{N: n, E: e}, nil
	case "EC":
		var curve elliptic.Curve
		switch k.Crv {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		case "P-521":
			curve = elliptic.P521()
		default:
			return nil, fmt.Errorf("unsupported EC curve %q", k.Crv)
		}
		xBytes, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil {
			return nil, fmt.Errorf("invalid EC x: %w", err)
		}
		yBytes, err := base64.RawURLEncoding.DecodeString(k.Y)
		if err != nil {
			return nil, fmt.Errorf("invalid EC y: %w", err)
		}
		return &ecdsa.PublicKey{
			Curve: curve,
			X:     new(big.Int).SetBytes(xBytes),
			Y:     new(big.Int).SetBytes(yBytes),
		}, nil
	default:
		return nil, fmt.Errorf("unsupported key type %q", k.Kty)
	}
}
