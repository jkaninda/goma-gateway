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
	"encoding/base64"
	"fmt"
	"os"
	"strings"
)

func (gatewayServer *GatewayServer) initTLS() ([]tls.Certificate, bool, error) {
	certs := loadTLS(gatewayServer.gateway.TLS)
	cert, err := loadGatewayCertificate(gatewayServer)
	if err == nil && cert != nil {
		certs = append(certs, *cert)
	}
	if len(certs) > 0 {
		return certs, true, nil
	}
	return nil, false, fmt.Errorf("failed to load TLS config")
}

// loadTLS initializes a TLS configuration by loading certificates from dynamic routes.
func loadTLS(t TLS) []tls.Certificate {
	certs := make([]tls.Certificate, 0)

	// Helper function to load certificates and append them to the config
	loadCertificates := func(t TLS, context string) {
		for _, key := range t.Keys {
			if key.Key == "" && key.Cert == "" {
				logger.Error(fmt.Sprintf("Error TLS: no certificate or key file provided for %s", context))
				continue
			}

			certificate, err := loadCertAndKey(key.Cert, key.Key)
			if err != nil {
				logger.Error(fmt.Sprintf("Error loading server certificate for %s: %v", context, err))
				continue
			}
			certs = append(certs, *certificate)
		}
	}

	// Load certificates for the gateway
	loadCertificates(t, "the gateway")

	// Load certificates for dynamic routes
	for _, route := range dynamicRoutes {
		loadCertificates(route.TLS, fmt.Sprintf("route: %s", route.Name))
	}

	return certs
}

// loadGatewayCertificate loads a certificate for the gateway server, handling both deprecated and new fields.
func loadGatewayCertificate(gatewayServer *GatewayServer) (*tls.Certificate, error) {
	loadCertificate := func(cert, key, warnMsg string) (*tls.Certificate, error) {
		if cert != "" || key != "" {
			if warnMsg != "" {
				logger.Warn("sslCertFile and sslKeyFile are deprecated, please use tlsCertFile and tlsKeyFile instead")
			}
			return loadCertAndKey(cert, key)
		}
		return nil, nil
	}

	// Check deprecated fields
	cert, err := loadCertificate(
		gatewayServer.gateway.SSLCertFile,
		gatewayServer.gateway.SSLKeyFile,
		"sslCertFile and sslKeyFile are deprecated, please use tlsCertFile and tlsKeyFile instead",
	)
	if err != nil {
		return cert, err
	}

	// Check new fields
	return loadCertificate(gatewayServer.gateway.TlsCertFile, gatewayServer.gateway.TlsKeyFile, "")
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
