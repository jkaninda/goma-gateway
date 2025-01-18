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
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/jkaninda/goma-gateway/pkg/logger"
	"os"
	"strings"
)

func (gatewayServer GatewayServer) initTLS() (*tls.Config, bool, error) {
	tlsConfig := loadTLS()
	cert, err := loadGatewayCertificate(gatewayServer)
	if err == nil {
		tlsConfig.Certificates = append(tlsConfig.Certificates, cert)
	}
	if tlsConfig != nil {
		return tlsConfig, true, nil
	}
	return nil, false, fmt.Errorf("failed to load TLS config")

}

// loadTLS loads TLS Certificate
func loadCert(cert, key string) (tls.Certificate, error) {
	if cert == "" && key == "" {
		return tls.Certificate{}, fmt.Errorf("no certificate or key file provided")
	}
	serverCert, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return serverCert, nil
}

func loadTLS() *tls.Config {
	cfg := &tls.Config{}
	for _, route := range dynamicRoutes {
		if len(route.TLS.Keys) > 0 {
			for _, key := range route.TLS.Keys {
				if key.Key == "" && key.Cert == "" {
					logger.Error("Error tls: no certificate or key file provided for route: %s", route.Name)
					continue
				}
				certificate, err := loadCertAndKey(key.Cert, key.Key)
				if err != nil {
					logger.Error("Error loading server certificate: %v", err)
					continue
				}
				cfg.Certificates = append(cfg.Certificates, certificate)
			}
		}

	}
	return cfg
}
func loadGatewayCertificate(gatewayServer GatewayServer) (tls.Certificate, error) {
	loadAndWarn := func(cert, key string, warnMsg string) (tls.Certificate, error) {
		if len(cert) != 0 || len(key) != 0 {
			if warnMsg != "" {
				logger.Warn("sslCertFile and sslKeyFile are deprecated, please use tlsCertFile and tlsKeyFile instead")
			}
			certificate, err := loadCertAndKey(cert, key)
			if err != nil {
				logger.Error("Error loading server certificate: %v", err)
			}
			return certificate, nil
		}
		return tls.Certificate{}, nil
	}
	// Check deprecated fields
	certificate, err := loadAndWarn(
		gatewayServer.gateway.SSLCertFile,
		gatewayServer.gateway.SSLKeyFile,
		"Warn",
	)
	if err != nil {
		return certificate, err
	}

	// Check new fields
	return loadAndWarn(
		gatewayServer.gateway.TlsCertFile,
		gatewayServer.gateway.TlsKeyFile,
		"",
	)
}

// / loadCertAndKey loads a certificate and private key from either file paths,
// raw PEM content, or base64-encoded content.
func loadCertAndKey(certInput, keyInput string) (tls.Certificate, error) {
	var certPEMBlock, keyPEMBlock []byte
	var err error

	// Helper function to decode base64 if the input is base64-encoded
	decodeBase64IfNeeded := func(input string) ([]byte, error) {
		trimmedInput := strings.TrimSpace(input)
		if isBase64(trimmedInput) {
			return base64.StdEncoding.DecodeString(trimmedInput)
		}
		return []byte(trimmedInput), nil
	}

	// Load certificate
	if strings.Contains(certInput, "-----BEGIN CERTIFICATE-----") {
		// Assume certInput is raw PEM content
		certPEMBlock = []byte(certInput)
	} else {
		// Check if certInput is base64-encoded
		decodedCert, err := decodeBase64IfNeeded(certInput)
		if err != nil {
			return tls.Certificate{}, fmt.Errorf("failed to decode base64 certificate: %w", err)
		}
		if strings.Contains(string(decodedCert), "-----BEGIN CERTIFICATE-----") {
			// Decoded content is PEM
			certPEMBlock = decodedCert
		} else {
			// Assume certInput is a file path
			certPEMBlock, err = os.ReadFile(certInput)
			if err != nil {
				return tls.Certificate{}, fmt.Errorf("failed to read certificate file: %w", err)
			}
		}
	}

	// Load private key
	if strings.Contains(keyInput, "-----BEGIN PRIVATE KEY-----") || strings.Contains(keyInput, "-----BEGIN RSA PRIVATE KEY-----") {
		// Assume keyInput is raw PEM content
		keyPEMBlock = []byte(keyInput)
	} else {
		// Check if keyInput is base64-encoded
		decodedKey, err := decodeBase64IfNeeded(keyInput)
		if err != nil {
			return tls.Certificate{}, fmt.Errorf("failed to decode base64 private key: %w", err)
		}
		if strings.Contains(string(decodedKey), "-----BEGIN PRIVATE KEY-----") || strings.Contains(string(decodedKey), "-----BEGIN RSA PRIVATE KEY-----") {
			// Decoded content is PEM
			keyPEMBlock = decodedKey
		} else {
			// Assume keyInput is a file path
			keyPEMBlock, err = os.ReadFile(keyInput)
			if err != nil {
				return tls.Certificate{}, fmt.Errorf("failed to read private key file: %w", err)
			}
		}
	}

	// Decode the PEM blocks to ensure they are valid
	certBlock, _ := pem.Decode(certPEMBlock)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		return tls.Certificate{}, errors.New("failed to decode PEM block containing certificate")
	}

	keyBlock, _ := pem.Decode(keyPEMBlock)
	if keyBlock == nil || (keyBlock.Type != "PRIVATE KEY" && keyBlock.Type != "RSA PRIVATE KEY") {
		return tls.Certificate{}, errors.New("failed to decode PEM block containing private key")
	}

	// Load the certificate and key into a tls.Certificate
	cert, err := tls.X509KeyPair(certPEMBlock, keyPEMBlock)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to load X509 key pair: %w", err)
	}

	return cert, nil
}

// isBase64 checks if the input is a valid Base64-encoded string.
func isBase64(input string) bool {
	_, err := base64.StdEncoding.DecodeString(input)
	return err == nil
}
