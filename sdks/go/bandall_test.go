// Conformance vectors: the same JSON every BandAll SDK must pass
// (`../conformance/vectors.json`).
package bandall

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// ADR-0015: the vectors are a versioned contract.
const schemaVersion = 1

type vectors struct {
	SchemaVersion int   `json:"schema_version"`
	NowSecs       int64 `json:"now_secs"`
	JWT     struct {
		JWKS     JWKS   `json:"jwks"`
		Issuer   string `json:"issuer"`
		Audience string `json:"audience"`
		Valid    string `json:"valid"`
		Tampered string `json:"tampered"`
		WrongAud string `json:"wrong_aud"`
		Expired  string `json:"expired"`
		NoneAlg  string `json:"none_alg"`
	} `json:"jwt"`
	HMAC struct {
		KeyHex    string `json:"key_hex"`
		Method    string `json:"method"`
		Path      string `json:"path"`
		Query     string `json:"query"`
		Body      string `json:"body"`
		Timestamp int64  `json:"timestamp"`
		Nonce     string `json:"nonce"`
		Canonical string `json:"canonical"`
		Signature string `json:"signature"`
	} `json:"hmac"`
}

func loadVectors(t *testing.T) *vectors {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "conformance", "vectors.json"))
	if err != nil {
		t.Fatalf("vectores compartidos: %v", err)
	}
	var v vectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("vectores inválidos: %v", err)
	}
	if v.SchemaVersion != schemaVersion {
		t.Fatalf("vectores versión %d, este SDK implementa %d", v.SchemaVersion, schemaVersion)
	}
	return &v
}

func TestConformanceJWT(t *testing.T) {
	v := loadVectors(t)

	claims, err := VerifyJWT(&v.JWT.JWKS, v.JWT.Valid, v.JWT.Issuer, v.JWT.Audience, v.NowSecs)
	if err != nil {
		t.Fatalf("el token válido debe verificar: %v", err)
	}
	if claims.Sub != "alice" || claims.Tenant != "acme" || claims.Aal != 1 {
		t.Fatalf("claims inesperados: %+v", claims)
	}

	// Un byte alterado en la firma es un token firmado por otra cosa.
	if _, err := VerifyJWT(&v.JWT.JWKS, v.JWT.Tampered, v.JWT.Issuer, v.JWT.Audience, v.NowSecs); err == nil {
		t.Fatal("el token alterado debe fallar")
	}

	if _, err := VerifyJWT(&v.JWT.JWKS, v.JWT.WrongAud, v.JWT.Issuer, "my-app", v.NowSecs); err == nil {
		t.Fatal("el token con otra audiencia debe fallar")
	}

	if _, err := VerifyJWT(&v.JWT.JWKS, v.JWT.Expired, v.JWT.Issuer, v.JWT.Audience, v.NowSecs); err == nil {
		t.Fatal("el token expirado debe fallar")
	}

	if _, err := VerifyJWT(&v.JWT.JWKS, v.JWT.NoneAlg, v.JWT.Issuer, v.JWT.Audience, v.NowSecs); err == nil {
		t.Fatal("alg=none debe fallar")
	}
}

func TestConformanceHMAC(t *testing.T) {
	v := loadVectors(t)

	req := &SignRequest{
		Method:    v.HMAC.Method,
		Path:      v.HMAC.Path,
		Query:     v.HMAC.Query,
		Body:      []byte(v.HMAC.Body),
		Timestamp: v.HMAC.Timestamp,
		Nonce:     v.HMAC.Nonce,
	}

	canonical, err := Canonical(req)
	if err != nil {
		t.Fatalf("canonical: %v", err)
	}
	if canonical != v.HMAC.Canonical {
		t.Fatalf("canonical no coincide:\n got %q\nwant %q", canonical, v.HMAC.Canonical)
	}

	sig, err := Sign(v.HMAC.KeyHex, req)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if sig != v.HMAC.Signature {
		t.Fatalf("firma no coincide:\n got %q\nwant %q", sig, v.HMAC.Signature)
	}

	if err := VerifySignature(v.HMAC.KeyHex, req, sig, v.HMAC.Timestamp, 300); err != nil {
		t.Fatalf("la firma correcta debe verificar: %v", err)
	}

	stale := *req
	stale.Timestamp = v.HMAC.Timestamp + 301
	if err := VerifySignature(v.HMAC.KeyHex, &stale, sig, v.HMAC.Timestamp, 300); err == nil {
		t.Fatal("una firma fuera de tolerancia debe fallar")
	}

	wrong := *req
	wrong.Nonce += "x"
	if err := VerifySignature(v.HMAC.KeyHex, &wrong, sig, v.HMAC.Timestamp, 300); err == nil {
		t.Fatal("una firma de otro mensaje debe fallar")
	}
}

func TestCanonicalRejectsNewlines(t *testing.T) {
	req := &SignRequest{Method: "POST\nEVIL", Timestamp: 1, Nonce: "n"}
	if _, err := Canonical(req); err == nil {
		t.Fatal("un campo con salto de línea debe ser rechazado")
	}
}

func TestFreshNonceIsUnique(t *testing.T) {
	a, err := FreshNonce()
	if err != nil {
		t.Fatalf("nonce: %v", err)
	}
	b, err := FreshNonce()
	if err != nil {
		t.Fatalf("nonce: %v", err)
	}
	if a == b {
		t.Fatal("dos nonces no deben coincidir")
	}
	if len(a) != 32 {
		t.Fatalf("nonce debe tener 128 bits en hex, tiene %d", len(a))
	}
}

func TestLeewayAllowsSkew(t *testing.T) {
	v := loadVectors(t)
	// exp del vector = 1700000600; `now = exp - 30` está dentro del leeway
	// de 60 s y debe verificar.
	claims, err := VerifyJWT(&v.JWT.JWKS, v.JWT.Valid, v.JWT.Issuer, v.JWT.Audience, 1700000570)
	if err != nil {
		t.Fatalf("dentro del leeway debe verificar: %v", err)
	}
	if claims.Exp != 1700000600 {
		t.Fatalf("exp inesperado: %d", claims.Exp)
	}
}