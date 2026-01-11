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
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	goutils "github.com/jkaninda/go-utils"
	"os"
	"strings"
	"sync"
)

func (g *Goma) initTLS() (bool, []tls.Certificate) {
	certs := g.loadTLS()
	if len(certs) > 0 {
		return true, certs
	}
	// load client CA
	if len(g.gateway.TLS.ClientAuth.ClientCA) > 0 {
		// Load certificates
		certPool, err := g.loadCertPool(g.gateway.TLS.ClientAuth.ClientCA)
		if err != nil {
			logger.Error("Failed to load client CA", "error", err)
			return false, certs
		}
		g.tlsCertPool = certPool
		g.tlsClientAuthRequired = g.gateway.TLS.ClientAuth.Required
	}
	return false, certs
}

// loadTLS initializes a TlsCertificates configuration by loading certificates from dynamic routes.
func (g *Goma) loadTLS() []tls.Certificate {
	var mu sync.Mutex
	certs := []tls.Certificate{}

	var wg sync.WaitGroup

	// load default Certificate
	if len(g.gateway.TLS.Default.Cert) > 0 && len(g.gateway.TLS.Default.Key) > 0 {
		certificate, err := loadCertAndKey(g.gateway.TLS.Default.Cert, g.gateway.TLS.Default.Key)
		if err != nil {
			logger.Error("Error loading default tls certificate", "error", err)
		} else {
			g.defaultCertificate = certificate
		}
	}

	// loadCertificates
	loadCertificates := func(t TlsCertificates, context string) {
		defer wg.Done()
		localCerts := []tls.Certificate{}

		for _, key := range t.Certificates {
			if key.Key == "" && key.Cert == "" {
				logger.Error(fmt.Sprintf("Error TlsCertificates: no certificate or key file provided for %s", context))
				continue
			}
			certificate, err := loadCertAndKey(goutils.ReplaceEnvVars(key.Cert), goutils.ReplaceEnvVars(key.Key))
			if err != nil {
				logger.Error(fmt.Sprintf("Error loading certificate for %s", context), "error", err)
				continue
			}
			localCerts = append(localCerts, *certificate)
		}

		mu.Lock()
		certs = append(certs, localCerts...)
		mu.Unlock()
	}

	wg.Add(1)
	go loadCertificates(g.gateway.TLS, "the gateway")

	for _, route := range g.dynamicRoutes {
		wg.Add(1)
		go loadCertificates(route.TLS, fmt.Sprintf("route: %s", route.Name))
	}

	wg.Wait()
	return certs
}

// loadCertPool loads certificate pool with better error handling
func (g *Goma) loadCertPool(clientCa string) (*x509.CertPool, error) {
	if len(clientCa) == 0 {
		return nil, nil
	}
	certPool, err := loadCertPool(clientCa)
	if err != nil {
		return nil, err
	}
	return certPool, nil
}

// loadCertAndKey loads a certificate and private key from file paths or raw PEM content.
func loadCertAndKey(certInput, keyInput string) (*tls.Certificate, error) {
	decodeBase64IfNeeded := func(input string) ([]byte, error) {
		trimmedInput := strings.TrimSpace(input)
		if isBase64(trimmedInput) {
			return base64.StdEncoding.DecodeString(trimmedInput)
		}
		return []byte(trimmedInput), nil
	}

	certPEMBlock, err := decodeCertOrKey(certInput, decodeBase64IfNeeded)
	if err != nil {
		return nil, fmt.Errorf("failed to process certificate: %w", err)
	}

	keyPEMBlock, err := decodeCertOrKey(keyInput, decodeBase64IfNeeded)
	if err != nil {
		return nil, fmt.Errorf("failed to process private key: %w", err)
	}

	cert, err := tls.X509KeyPair(certPEMBlock, keyPEMBlock)
	if err != nil {
		return nil, fmt.Errorf("failed to load X509 key pair: %w", err)
	}

	return &cert, nil
}
func loadCertPool(rootCA string) (*x509.CertPool, error) {
	certPool := x509.NewCertPool()
	if rootCA == "" {
		// Load system root CAs
		systemCertPool, err := x509.SystemCertPool()
		if err != nil {
			systemCertPool = x509.NewCertPool()
		}
		return systemCertPool, nil
	}

	decodeBase64IfNeeded := func(input string) ([]byte, error) {
		trimmedInput := strings.TrimSpace(input)
		if isBase64(trimmedInput) {
			return base64.StdEncoding.DecodeString(trimmedInput)
		}
		return []byte(trimmedInput), nil
	}

	certPEMBlock, err := decodeCertOrKey(rootCA, decodeBase64IfNeeded)
	if err != nil {
		return nil, fmt.Errorf("failed to process certificate: %w", err)
	}
	if ok := certPool.AppendCertsFromPEM(certPEMBlock); !ok {
		return nil, errors.New("failed to parse root certificate")
	}

	return certPool, nil
}

// decodeCertOrKey processes PEM or file-based input.
func decodeCertOrKey(input string, decodeBase64 func(string) ([]byte, error)) ([]byte, error) {
	if strings.Contains(input, "-----BEGIN") {
		return []byte(input), nil
	}

	decoded, err := decodeBase64(input)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64 content: %w", err)
	}

	if strings.Contains(string(decoded), "-----BEGIN") {
		return decoded, nil
	}

	return os.ReadFile(input)
}

// isBase64 checks if the input is valid Base64-encoded content.
func isBase64(input string) bool {
	_, err := base64.StdEncoding.DecodeString(input)
	return err == nil
}
func startAutoCert(routes []Route) {
	logger.Debug("Initializing certificate manager...")
	err := certManager.Initialize()
	if err != nil {
		return
	}
	logger.Debug("Starting AutoCert service")
	if certManager != nil && certManager.AcmeInitialized() {
		certManager.AutoCert(hostNames(routes))
	}

}
