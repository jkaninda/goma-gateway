package middlewares

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"testing"
)

func TestParseECDSAPublicKeyRoundTrip(t *testing.T) {
	for name, curve := range map[string]elliptic.Curve{"P-256": elliptic.P256(), "P-384": elliptic.P384(), "P-521": elliptic.P521()} {
		key, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		size := (curve.Params().BitSize + 7) / 8
		x := key.X.FillBytes(make([]byte, size))
		y := key.Y.FillBytes(make([]byte, size))
		got, err := parseECDSAPublicKey(name, base64.RawURLEncoding.EncodeToString(x), base64.RawURLEncoding.EncodeToString(y))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !got.Equal(&key.PublicKey) {
			t.Errorf("%s: parsed key differs from the original", name)
		}
	}
	// A point that is not on the curve must be rejected, not accepted as a key.
	bad := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	if _, err := parseECDSAPublicKey("P-256", bad, bad); err == nil {
		t.Error("point not on the curve was accepted")
	}
}
