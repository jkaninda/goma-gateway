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
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/jkaninda/goma-gateway/pkg/middlewares"
	"io"
	"os"
	"strings"
)

// loadRSAPublicKey loads an RSA public key from a PEM file or raw PEM content.
func loadRSAPublicKey(input string) (*rsa.PublicKey, error) {
	var data []byte
	var err error

	trimmed := strings.TrimSpace(input)

	switch {
	case strings.Contains(trimmed, "-----BEGIN"):
		// Raw PEM content
		data = []byte(trimmed)

	case isBase64(trimmed):
		// Base64-encoded PEM content
		data, err = base64.StdEncoding.DecodeString(trimmed)
		if err != nil {
			return nil, fmt.Errorf("failed to decode base64 input: %w", err)
		}

	default:
		// File path to PEM file
		data, err = os.ReadFile(trimmed)
		if err != nil {
			return nil, fmt.Errorf("failed to read PEM file: %w", err)
		}
	}

	// Decode PEM block
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("invalid PEM format")
	}

	// Handle different PEM block types
	switch block.Type {
	case "PUBLIC KEY":
		key, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse public key: %w", err)
		}
		rsaKey, ok := key.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("key is not an RSA public key")
		}
		return rsaKey, nil

	case "CERTIFICATE":
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate: %w", err)
		}
		rsaKey, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("certificate does not contain an RSA public key")
		}
		return rsaKey, nil

	default:
		return nil, fmt.Errorf("unsupported PEM block type: %s", block.Type)
	}
}

func loadJWKSFromFile(jwksInput string) (*middlewares.Jwks, error) {
	trimmed := strings.TrimSpace(jwksInput)

	var reader io.Reader

	if isBase64(trimmed) {
		decoded, err := base64.StdEncoding.DecodeString(trimmed)
		if err != nil {
			return nil, fmt.Errorf("failed to decode base64 JWKS content: %w", err)
		}
		reader = bytes.NewReader(decoded)
	} else {
		file, err := os.Open(trimmed)
		if err != nil {
			return nil, fmt.Errorf("failed to open JWKS file: %w", err)
		}
		defer func() {
			if cerr := file.Close(); cerr != nil {
				logger.Error("Error closing JWKS file", "error", cerr)
			}
		}()
		reader = file
	}

	var keySet middlewares.Jwks
	if err := json.NewDecoder(reader).Decode(&keySet); err != nil {
		return nil, fmt.Errorf("failed to decode JWKS content: %w", err)
	}

	return &keySet, nil
}
