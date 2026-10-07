// BandAll thin Go SDK: offline JWT (EdDSA) verification and HMAC request
// signatures (H6). Mirrors the TypeScript/Python/C# SDKs over the shared
// conformance vectors in `../conformance/vectors.json`.
//
// Package bandall implements the two shapes a relying service needs: validate
// a BandAll access token without network calls, and sign/verify webhook and
// API requests.
package bandall

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// LeewaySecs is the clock skew tolerated for `exp` in access tokens.
const LeewaySecs = 60

var b64 = base64.RawURLEncoding

// JWK is a single Ed25519 public key in the JWKS shape BandAll serves.
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	X   string `json:"x"`
}

// JWKS is the document BandAll serves at /.well-known/jwks.json.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// Claims are the fields a relying service may read after verification.
type Claims struct {
	Iss    string   `json:"iss"`
	Aud    string   `json:"aud"`
	Sub    string   `json:"sub"`
	Tenant string   `json:"tenant"`
	Sid    string   `json:"sid"`
	Amr    []string `json:"amr"`
	Aal    int      `json:"aal"`
	Jti    string   `json:"jti"`
	Iat    int64    `json:"iat"`
	Exp    int64    `json:"exp"`
}

// VerifyJWT strictly verifies a BandAll access token against the JWKS:
// fixed `EdDSA` algorithm, known `kid`, Ed25519 signature, then
// `iss`/`aud`/`exp`. Returns the claims, or an error with no internals.
func VerifyJWT(jwks *JWKS, token, issuer, audience string, now int64) (*Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("malformed token")
	}
	headerJSON, err := b64.DecodeString(parts[0])
	if err != nil {
		return nil, errors.New("malformed header encoding")
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, errors.New("malformed header")
	}
	if header.Alg != "EdDSA" || header.Kid == "" {
		return nil, errors.New("unexpected algorithm")
	}
	var key *JWK
	for i := range jwks.Keys {
		if jwks.Keys[i].Kid == header.Kid && jwks.Keys[i].Crv == "Ed25519" {
			key = &jwks.Keys[i]
			break
		}
	}
	if key == nil {
		return nil, errors.New("unknown key id")
	}
	rawX, err := b64.DecodeString(key.X)
	if err != nil || len(rawX) != ed25519.PublicKeySize {
		return nil, errors.New("invalid public key")
	}
	sig, err := b64.DecodeString(parts[2])
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, errors.New("invalid signature")
	}
	signingInput := parts[0] + "." + parts[1]
	if !ed25519.Verify(ed25519.PublicKey(rawX), []byte(signingInput), sig) {
		return nil, errors.New("bad signature")
	}
	claimsJSON, err := b64.DecodeString(parts[1])
	if err != nil {
		return nil, errors.New("malformed claims encoding")
	}
	var claims Claims
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		return nil, errors.New("malformed claims")
	}
	if claims.Iss != issuer || claims.Aud != audience {
		return nil, errors.New("issuer or audience mismatch")
	}
	if claims.Exp < now-LeewaySecs {
		return nil, errors.New("token expired")
	}
	return &claims, nil
}

// SignRequest holds the components of a request to sign.
type SignRequest struct {
	Method    string
	Path      string
	Query     string
	Body      []byte
	Timestamp int64
	Nonce     string
}

// Canonical builds the canonical string: METHOD\nPATH\nQUERY\nSHA256(body)\ntimestamp\nnonce.
func Canonical(req *SignRequest) (string, error) {
	for _, part := range []string{req.Method, req.Path, req.Query, req.Nonce} {
		if strings.ContainsAny(part, "\n\r") {
			return "", errors.New("malformed field")
		}
	}
	bodyHash := sha256.Sum256(req.Body)
	return fmt.Sprintf("%s\n%s\n%s\n%s\n%d\n%s",
		strings.ToUpper(req.Method), req.Path, req.Query,
		hex.EncodeToString(bodyHash[:]), req.Timestamp, req.Nonce), nil
}

// Sign returns the `v1=<hex>` signature of the canonical string.
func Sign(keyHex string, req *SignRequest) (string, error) {
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return "", errors.New("invalid key")
	}
	canonical, err := Canonical(req)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(canonical))
	return "v1=" + hex.EncodeToString(mac.Sum(nil)), nil
}

// VerifySignature checks structure, clock tolerance and signature in
// constant time. Replay is the caller's responsibility (a store keyed by
// nonce); this function keeps the same surface as the other SDKs.
func VerifySignature(keyHex string, req *SignRequest, presented string, now int64, clockToleranceSecs int64) error {
	if clockToleranceSecs == 0 {
		clockToleranceSecs = 300
	}
	if req.Timestamp < now-clockToleranceSecs || req.Timestamp > now+clockToleranceSecs {
		return errors.New("stale timestamp")
	}
	expected, err := Sign(keyHex, req)
	if err != nil {
		return err
	}
	if len(presented) != len(expected) {
		return errors.New("bad signature")
	}
	if subtle.ConstantTimeCompare([]byte(expected), []byte(presented)) != 1 {
		return errors.New("bad signature")
	}
	return nil
}

// FreshNonce returns 128 random bits in hex, for one-shot signatures.
func FreshNonce() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

// nowFunc is the clock seam so tests can fix the time.
var nowFunc = time.Now

// Now returns Unix seconds.
func Now() int64 {
	return nowFunc().Unix()
}