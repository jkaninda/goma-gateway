/*
 * Copyright 2024 Jonas Kaninda
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package internal

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jkaninda/goma-gateway/pkg/certmanager"
)

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

func servedCertificate(t *testing.T, g *Goma, host string) []byte {
	t.Helper()
	cm, err := certmanager.NewCertManager(nil)
	if err != nil {
		t.Fatalf("new cert manager: %v", err)
	}
	_, certs := g.initTLS()
	cm.AddCertificates(certs)
	cert, err := cm.GetCertificate(&tls.ClientHelloInfo{ServerName: host})
	if err != nil || cert == nil {
		t.Fatalf("no certificate served for %s: %v", host, err)
	}
	return cert.Certificate[0]
}

func pemDER(t *testing.T, certPEM string) []byte {
	t.Helper()
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		t.Fatal("invalid PEM")
	}
	return block.Bytes
}

func TestLoadTLSPrecedenceForSameHost(t *testing.T) {
	const host = "example.com"
	dir := t.TempDir()
	dirCert, dirKey := generateTestCert(t, host)
	if err := os.WriteFile(filepath.Join(dir, host+".crt"), []byte(dirCert), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, host+".key"), []byte(dirKey), 0o600); err != nil {
		t.Fatal(err)
	}
	gwCert, gwKey := generateTestCert(t, host)
	routeCert, routeKey := generateTestCert(t, host)

	gateway := &Gateway{TLS: TlsCertificates{
		CertsDir:     dir,
		Certificates: []TLS{{Cert: gwCert, Key: gwKey}},
	}}
	route := Route{Name: "r", TLS: TlsCertificate{Certificate: TLS{Cert: routeCert, Key: routeKey}}}

	// Loading runs concurrently, so repeat to catch order-dependent results.
	for i := 0; i < 20; i++ {
		g := &Goma{gateway: gateway, dynamicRoutes: []Route{route}}
		if got := servedCertificate(t, g, host); !bytes.Equal(got, pemDER(t, routeCert)) {
			t.Fatalf("run %d: route certificate should win over gateway and directory certificates", i)
		}
	}

	for i := 0; i < 20; i++ {
		g := &Goma{gateway: gateway}
		if got := servedCertificate(t, g, host); !bytes.Equal(got, pemDER(t, gwCert)) {
			t.Fatalf("run %d: gateway certificate should win over directory certificate", i)
		}
	}
}

func TestInitTLSLoadsClientCAWithCertificates(t *testing.T) {
	cert, key := generateTestCert(t, "example.com")
	caCert, _ := generateTestCert(t, "client-ca")
	g := &Goma{gateway: &Gateway{TLS: TlsCertificates{
		CertsDir:     t.TempDir(),
		Certificates: []TLS{{Cert: cert, Key: key}},
		ClientAuth:   TLSClientAuth{ClientCA: caCert, Required: true},
	}}}

	ok, certs := g.initTLS()
	if !ok || len(certs) != 1 {
		t.Fatalf("expected one certificate, got ok=%v len=%d", ok, len(certs))
	}
	if g.tlsCertPool == nil {
		t.Fatal("client CA was not loaded when certificates are configured")
	}
	if !g.tlsClientAuthRequired {
		t.Fatal("clientAuth.required was not applied")
	}
}
