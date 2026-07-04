/*
Copyright 2024 Jonas Kaninda

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package certmanager

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// clearVaultEnv unsets the Vault environment variables (which take precedence
// over config) so tests exercise the config-driven values, restoring them
// afterwards.
func clearVaultEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{"VAULT_ADDR", "VAULT_TOKEN", "VAULT_NAMESPACE"} {
		if v, ok := os.LookupEnv(k); ok {
			_ = os.Unsetenv(k)
			t.Cleanup(func() { _ = os.Setenv(k, v) })
		}
	}
}

// generateTestCert returns a self-signed certificate and key in PEM form to
// stand in for a Vault-issued certificate.
func generateTestCert(t *testing.T, cn string) (string, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     []string{cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(72 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	return certPEM, keyPEM
}

// newVaultStub returns an httptest server that mimics the Vault PKI issue
// endpoint and records the last request path and token it saw.
func newVaultStub(t *testing.T, certPEM, keyPEM string, gotPath, gotToken *string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*gotPath = r.URL.Path
		*gotToken = r.Header.Get("X-Vault-Token")
		resp := map[string]any{
			"data": map[string]any{
				"certificate":      certPEM,
				"issuing_ca":       certPEM,
				"ca_chain":         []string{certPEM},
				"private_key":      keyPEM,
				"private_key_type": "rsa",
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
}

func TestVaultIssueAndStore(t *testing.T) {
	clearVaultEnv(t)
	certPEM, keyPEM := generateTestCert(t, "example.com")
	var gotPath, gotToken string
	srv := newVaultStub(t, certPEM, keyPEM, &gotPath, &gotToken)
	defer srv.Close()

	cfg := ProviderConfig{
		Type: CertVaultProvider,
		Vault: Vault{
			Address:     srv.URL,
			Token:       "s.test-token",
			Role:        "my-role",
			StorageFile: filepath.Join(t.TempDir(), "vault.json"),
		},
	}
	p, err := newProvider("vault", cfg)
	if err != nil {
		t.Fatalf("newProvider: %v", err)
	}
	if err := p.initialize(); err != nil {
		t.Fatalf("initialize: %v", err)
	}
	if !p.acmeInitialized {
		t.Fatal("expected vault provider to be initialized")
	}

	cert, err := p.performVaultCertificateRequest(Domain{Name: "route", Hosts: []string{"example.com"}})
	if err != nil {
		t.Fatalf("performVaultCertificateRequest: %v", err)
	}
	if cert == nil {
		t.Fatal("expected a certificate")
	}

	if gotPath != "/v1/pki/issue/my-role" {
		t.Errorf("request path = %q, want %q", gotPath, "/v1/pki/issue/my-role")
	}
	if gotToken != "s.test-token" {
		t.Errorf("vault token header = %q, want %q", gotToken, "s.test-token")
	}

	if got := p.findCertificateInfo("example.com"); got == nil {
		t.Fatal("certificate was not stored for example.com")
	} else if got.Expires.Before(time.Now()) {
		t.Errorf("stored certificate already expired: %v", got.Expires)
	}
}

func TestVaultCustomMountAndTTL(t *testing.T) {
	clearVaultEnv(t)
	certPEM, keyPEM := generateTestCert(t, "svc.internal")
	var gotPath, gotToken string
	srv := newVaultStub(t, certPEM, keyPEM, &gotPath, &gotToken)
	defer srv.Close()

	client, err := newVaultPKIClient(Vault{
		Address: srv.URL,
		Token:   "tok",
		Role:    "web",
		Mount:   "pki_int",
		Ttl:     "48h",
	})
	if err != nil {
		t.Fatalf("newVaultPKIClient: %v", err)
	}
	if _, err := client.IssueCertificate([]string{"svc.internal", "alt.internal"}); err != nil {
		t.Fatalf("IssueCertificate: %v", err)
	}
	if gotPath != "/v1/pki_int/issue/web" {
		t.Errorf("request path = %q, want %q", gotPath, "/v1/pki_int/issue/web")
	}
}

func TestNewVaultPKIClientValidation(t *testing.T) {
	clearVaultEnv(t)
	cases := []struct {
		name string
		cfg  Vault
	}{
		{"missing address", Vault{Token: "t", Role: "r"}},
		{"missing token", Vault{Address: "https://v", Role: "r"}},
		{"missing role", Vault{Address: "https://v", Token: "t"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := newVaultPKIClient(tc.cfg); err == nil {
				t.Fatalf("expected error for %s", tc.name)
			}
		})
	}

	// Defaults: mount falls back to "pki".
	c, err := newVaultPKIClient(Vault{Address: "https://v", Token: "t", Role: "r"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.mount != defaultVaultMount {
		t.Errorf("mount = %q, want %q", c.mount, defaultVaultMount)
	}
}
