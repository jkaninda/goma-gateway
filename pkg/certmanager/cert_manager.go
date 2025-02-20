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
	"math/big"
	"os"
	"strings"
	"sync"
	"time"
)

// CertManager dynamically loads TLS certificates.
type CertManager struct {
	mu          sync.RWMutex
	certs       map[string]*tls.Certificate
	defaultCert *tls.Certificate // Fallback for unknown domains

}

// NewCertManager initializes the certificate manager.
func NewCertManager() *CertManager {
	return &CertManager{
		certs: make(map[string]*tls.Certificate),
	}
}

// LoadCertificate loads a TLS certificate from files.
func (cm *CertManager) LoadCertificate(domain, certFile, keyFile string) error {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return err
	}
	cm.mu.Lock()
	defer cm.mu.Unlock()
	if domain == "default" {
		cm.defaultCert = &cert
	} else {
		cm.certs[domain] = &cert
	}
	return nil
}

// UpdateCertificate updates a TLS certificate from Certificate.
func (cm *CertManager) UpdateCertificate(domain string, cert tls.Certificate) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	if domain == "default" {
		cm.defaultCert = &cert
	} else {
		cm.certs[domain] = &cert
	}
}

// GetCertificate dynamically retrieves the certificate for the given ClientHello request.
func (cm *CertManager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	// Check for exact domain match
	if cert, exists := cm.certs[hello.ServerName]; exists {
		return cert, nil
	}

	// Check for a wildcard match
	wildcardDomain := getWildcardDomain(hello.ServerName)
	if wildcardCert, exists := cm.certs[wildcardDomain]; exists {
		return wildcardCert, nil
	}

	// Use default certificate if no match found
	if cm.defaultCert != nil {
		return cm.defaultCert, nil
	}

	return nil, os.ErrNotExist
}

// GenerateCertificate generates a self-signed certificate for the given domain.
func (cm *CertManager) GenerateCertificate(domain string) (*tls.Certificate, error) {
	// Generate a private key
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %v", err)
	}
	// Create a certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: domain,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	// Create the certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %v", err)
	}
	// Encode the private key and certificate
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	// Create a TLS certificate
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to create TLS certificate: %v", err)
	}
	cm.mu.Lock()
	defer cm.mu.Unlock()
	cm.certs[domain] = &tlsCert
	return &tlsCert, nil
}

// GenerateDefaultCertificate generates a default self-signed certificate.
func (cm *CertManager) GenerateDefaultCertificate() (*tls.Certificate, error) {
	return cm.GenerateCertificate("GOMA DEFAULT CERT")
}

// WatchCerts watches for certificate changes and reloads them dynamically.
func (cm *CertManager) WatchCerts(domain, certFile, keyFile string, interval time.Duration) {

}

// getWildcardDomain
func getWildcardDomain(domain string) string {
	parts := strings.Split(domain, ".")
	if len(parts) > 2 {
		return "*." + strings.Join(parts[1:], ".")
	}
	return ""
}
