package oidc

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func signedRS256(t *testing.T, key *rsa.PrivateKey, kid string, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	if kid != "" {
		tok.Header["kid"] = kid
	}
	s, err := tok.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestVerifyWithKeys(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keys := map[string]crypto.PublicKey{"kid1": &key.PublicKey}
	validClaims := jwt.MapClaims{"sub": "alice", "iss": "https://op.example.com", "exp": time.Now().Add(time.Hour).Unix()}

	t.Run("valid RS256 token accepted", func(t *testing.T) {
		claims, err := verifyWithKeys(signedRS256(t, key, "kid1", validClaims), keys)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if claims["sub"] != "alice" {
			t.Fatalf("sub = %v, want alice", claims["sub"])
		}
	})

	t.Run("tampered payload rejected", func(t *testing.T) {
		tok := signedRS256(t, key, "kid1", validClaims)
		// Flip a character in the payload segment.
		b := []byte(tok)
		b[len(b)/2] ^= 0x01
		if _, err := verifyWithKeys(string(b), keys); !errors.Is(err, ErrTokenInvalid) {
			t.Fatalf("err = %v, want ErrTokenInvalid", err)
		}
	})

	t.Run("expired token rejected", func(t *testing.T) {
		expired := jwt.MapClaims{"sub": "alice", "exp": time.Now().Add(-time.Hour).Unix()}
		if _, err := verifyWithKeys(signedRS256(t, key, "kid1", expired), keys); !errors.Is(err, ErrTokenInvalid) {
			t.Fatalf("err = %v, want ErrTokenInvalid", err)
		}
	})

	t.Run("unknown kid rejected", func(t *testing.T) {
		if _, err := verifyWithKeys(signedRS256(t, key, "other", validClaims), keys); !errors.Is(err, ErrTokenInvalid) {
			t.Fatalf("err = %v, want ErrTokenInvalid", err)
		}
	})

	t.Run("alg none rejected", func(t *testing.T) {
		header, _ := json.Marshal(map[string]string{"alg": "none", "typ": "JWT"})
		payload, _ := json.Marshal(validClaims)
		noneTok := b64(header) + "." + b64(payload) + "."
		if _, err := verifyWithKeys(noneTok, keys); !errors.Is(err, ErrTokenInvalid) {
			t.Fatalf("err = %v, want ErrTokenInvalid", err)
		}
	})

	t.Run("HMAC alg-confusion rejected", func(t *testing.T) {
		// In an algorithm-confusion attack the token is HS256-signed using the
		// provider's public key material as the shared secret. Restricting the
		// accepted algorithms to asymmetric ones must reject any HS* token
		// before its signature is ever checked, regardless of the secret used.
		tok := jwt.NewWithClaims(jwt.SigningMethodHS256, validClaims)
		tok.Header["kid"] = "kid1"
		hs, err := tok.SignedString([]byte("attacker-chosen-secret"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := verifyWithKeys(hs, keys); !errors.Is(err, ErrTokenInvalid) {
			t.Fatalf("err = %v, want ErrTokenInvalid", err)
		}
	})
}

func TestKeyfuncForNoKid(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	claims := jwt.MapClaims{"sub": "a", "exp": time.Now().Add(time.Hour).Unix()}

	t.Run("no kid single key accepted", func(t *testing.T) {
		keys := map[string]crypto.PublicKey{"": &key.PublicKey}
		if _, err := verifyWithKeys(signedRS256(t, key, "", claims), keys); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("no kid multiple keys rejected", func(t *testing.T) {
		other, _ := rsa.GenerateKey(rand.Reader, 2048)
		keys := map[string]crypto.PublicKey{"a": &key.PublicKey, "b": &other.PublicKey}
		if _, err := verifyWithKeys(signedRS256(t, key, "", claims), keys); !errors.Is(err, ErrTokenInvalid) {
			t.Fatalf("err = %v, want ErrTokenInvalid", err)
		}
	})
}

func TestJWKPublicKey(t *testing.T) {
	t.Run("RSA reconstructed", func(t *testing.T) {
		key, _ := rsa.GenerateKey(rand.Reader, 2048)
		k := jwk{
			Kty: "RSA",
			N:   b64(key.PublicKey.N.Bytes()),
			E:   b64(big.NewInt(int64(key.PublicKey.E)).Bytes()),
		}
		pub, err := k.publicKey()
		if err != nil {
			t.Fatal(err)
		}
		rp, ok := pub.(*rsa.PublicKey)
		if !ok || rp.N.Cmp(key.PublicKey.N) != 0 || rp.E != key.PublicKey.E {
			t.Fatalf("reconstructed key does not match original")
		}
	})

	t.Run("weak RSA rejected", func(t *testing.T) {
		key, _ := rsa.GenerateKey(rand.Reader, 1024)
		k := jwk{Kty: "RSA", N: b64(key.PublicKey.N.Bytes()), E: b64(big.NewInt(int64(key.PublicKey.E)).Bytes())}
		if _, err := k.publicKey(); err == nil {
			t.Fatal("expected weak RSA key to be rejected")
		}
	})

	t.Run("EC reconstructed", func(t *testing.T) {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		k := jwk{Kty: "EC", Crv: "P-256", X: b64(key.PublicKey.X.Bytes()), Y: b64(key.PublicKey.Y.Bytes())}
		pub, err := k.publicKey()
		if err != nil {
			t.Fatal(err)
		}
		ep, ok := pub.(*ecdsa.PublicKey)
		if !ok || ep.X.Cmp(key.PublicKey.X) != 0 || ep.Y.Cmp(key.PublicKey.Y) != 0 {
			t.Fatalf("reconstructed EC key does not match original")
		}
	})

	t.Run("unsupported kty rejected", func(t *testing.T) {
		if _, err := (jwk{Kty: "oct"}).publicKey(); err == nil {
			t.Fatal("expected unsupported kty to be rejected")
		}
	})
}
