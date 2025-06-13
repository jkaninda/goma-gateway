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

package certmanager

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/jkaninda/logger"
	"golang.org/x/crypto/acme/autocert"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// CertManager dynamically manages TLS certificates.
type CertManager struct {
	mu              sync.RWMutex
	certs           map[string]*tls.Certificate
	defaultCert     *tls.Certificate
	autoCertManager *autocert.Manager
}

// NewCertManager initializes a CertManager instance.
func NewCertManager() *CertManager {
	return &CertManager{
		certs:           make(map[string]*tls.Certificate),
		autoCertManager: &autocert.Manager{},
	}
}

// LoadCertificate loads a TLS certificate from files.
func (cm *CertManager) LoadCertificate(domain, certFile, keyFile string) error {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return err
	}
	cm.AddCertificate(domain, cert)
	return nil
}

// AddCertificate adds a TLS certificate.
func (cm *CertManager) AddCertificate(domain string, cert tls.Certificate) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	if domain == "default" {
		cm.defaultCert = &cert
	} else {
		cm.certs[domain] = &cert
	}
}

// AddCertificates adds multiple TLS certificates.
func (cm *CertManager) AddCertificates(certs []tls.Certificate) {
	for _, cert := range certs {
		commonName, sanNames, err := getCertificateDetails(&cert)
		if err != nil {
			continue
		}
		for _, domain := range append([]string{commonName}, sanNames...) {
			if domain != "" {
				cm.AddCertificate(domain, cert)
			}
		}
	}
}

// GetCertificate retrieves the appropriate certificate for a given ClientHello request.
func (cm *CertManager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	cm.mu.RLock()
	cert := cm.findCertificate(hello.ServerName)
	cm.mu.RUnlock()

	if cert != nil {
		logger.Debug("Serving certificate",
			"server_name", hello.ServerName,
			"type", "manual",
		)
		return cert, nil
	}

	if cm.autoCertManager != nil {
		acmeCert, err := cm.autoCertManager.GetCertificate(hello)
		if err == nil {
			logger.Debug("Serving certificate",
				"server_name", hello.ServerName,
				"type", "autocert",
			)
			return acmeCert, nil
		}
		logger.Error("autocert manager failed",
			"server_name", hello.ServerName,
			"error", err.Error(),
		)
	}

	if cm.defaultCert != nil {
		logger.Debug("Serving default certificate",
			"server_name", hello.ServerName,
			"type", "default",
		)
		return cm.defaultCert, nil
	}

	logger.Debug("No matching certificate found",
		"server_name", hello.ServerName,
	)
	return nil, os.ErrNotExist
}

func (cm *CertManager) AutoCertHandler(router *mux.Router) http.HandlerFunc {
	acmeHandler := cm.autoCertManager.HTTPHandler(nil)
	return func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/.well-known/acme-challenge/") {
			acmeHandler.ServeHTTP(w, r)
			return
		}
		router.ServeHTTP(w, r)
	}
}

// findCertificate searches for a certificate by exact, wildcard, or parent domain match.
func (cm *CertManager) findCertificate(domain string) *tls.Certificate {
	if cert, exists := cm.certs[domain]; exists {
		return cert
	}
	for _, d := range []string{getWildcardDomain(domain), getParentDomain(domain)} {
		if cert, exists := cm.certs[d]; exists {
			return cert
		}
	}
	return nil
}

// GenerateCertificate creates a self-signed certificate for a domain.
func (cm *CertManager) GenerateCertificate(domain string) (*tls.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: domain},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		logger.Error("Failed to generate self-signed certificate",
			"domain", domain,
			"error", err.Error(),
		)
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {

		return nil, fmt.Errorf("failed to create TLS certificate: %w", err)
	}

	cm.AddCertificate(domain, tlsCert)
	logger.Debug("Self-signed certificate generated",
		"domain", domain,
	)
	return &tlsCert, nil
}

// GenerateDefaultCertificate creates a self-signed default certificate.
func (cm *CertManager) GenerateDefaultCertificate() (*tls.Certificate, error) {
	return cm.GenerateCertificate("GOMA DEFAULT CERT")
}

// getWildcardDomain returns the wildcard domain for a given domain.
func getWildcardDomain(domain string) string {
	parts := strings.Split(domain, ".")
	if len(parts) > 2 {
		return "*." + strings.Join(parts[1:], ".")
	}
	return ""
}

func (cm *CertManager) AutoCert(hosts []string, cacheDir string) {
	jsonCache, err := newJSONCache(filepath.Join(cacheDir, "certificates.json"))
	if err != nil {
		logger.Error("Failed to create JSON cache", "error", err)
		return
	}
	cm.autoCertManager = &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(hosts...),
		Cache:      jsonCache,
	}
}

// getParentDomain returns the parent domain for a given domain.
func getParentDomain(domain string) string {
	parts := strings.Split(domain, ".")
	if len(parts) > 2 {
		return strings.Join(parts[1:], ".")
	}
	return ""
}

// getCertificateDetails extracts the Subject (CN) and SANs from a TLS certificate.
func getCertificateDetails(cert *tls.Certificate) (string, []string, error) {
	if cert == nil || len(cert.Certificate) == 0 {
		return "", nil, fmt.Errorf("no certificate data found")
	}

	parsedCert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return "", nil, fmt.Errorf("failed to parse certificate: %v", err)
	}

	return parsedCert.Subject.CommonName, parsedCert.DNSNames, nil
}
