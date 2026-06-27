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
	"fmt"

	"github.com/jkaninda/encryptor"
	goutils "github.com/jkaninda/go-utils"
)

// EncryptionKeyEnv is the environment variable holding the passphrase used to
// decrypt encrypted configuration fields (middleware rules and TLS material).
const EncryptionKeyEnv = "GOMA_CONFIG_ENCRYPTION_KEY"

// encryptionPassphrase returns the configured passphrase, or an empty string
// when encryption is not enabled.
func encryptionPassphrase() string {
	return goutils.Env(EncryptionKeyEnv, "")
}

// decryptValue decrypts s when it is an encrypted (PGP-armored) value. Plaintext
// values are returned unchanged so encrypted and plaintext configuration can be
// mixed during migration. An encrypted value with no passphrase configured is an
// error so the gateway never boots with unusable secrets.
func decryptValue(s string) (string, error) {
	if !encryptor.IsEncrypted(s) {
		return s, nil
	}
	pass := encryptionPassphrase()
	if pass == "" {
		return "", fmt.Errorf("encrypted value found but %s is not set", EncryptionKeyEnv)
	}
	data, err := encryptor.DecryptString(s, pass)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt value: %w", err)
	}
	return string(data), nil
}

// decryptConfig decrypts every encrypted field in the assembled configuration:
// middleware rules and all TLS certificate/key material (gateway-level and
// per-route). It runs once per load/reload, after all sources (main file, extra
// config and providers) have been merged.
func (g *Goma) decryptConfig() error {
	if err := decryptTLSCertificates(&g.gateway.TLS); err != nil {
		return fmt.Errorf("gateway tls: %w", err)
	}
	for i := range g.dynamicRoutes {
		route := &g.dynamicRoutes[i]
		if err := decryptTLS(&route.TLS.Certificate); err != nil {
			return fmt.Errorf("route %q tls: %w", route.Name, err)
		}
	}
	for i := range g.dynamicMiddlewares {
		if err := decryptMiddlewareRule(&g.dynamicMiddlewares[i]); err != nil {
			return err
		}
	}
	return nil
}

// decryptMiddlewareRule decrypts an encrypted middleware rule and decodes it into
// the type-specific rule structure. Rules that were not encrypted are decoded at
// unmarshal time and reach this function already typed, so they are left as-is.
func decryptMiddlewareRule(m *Middleware) error {
	raw, ok := m.Rule.(string)
	if !ok || !encryptor.IsEncrypted(raw) {
		return nil
	}
	plain, err := decryptValue(raw)
	if err != nil {
		return fmt.Errorf("middleware %q rule: %w", m.Name, err)
	}
	rule, err := decodeRuleBytes(m.Type, []byte(plain))
	if err != nil {
		return fmt.Errorf("middleware %q rule: %w", m.Name, err)
	}
	m.Rule = rule
	return nil
}

// decryptTLSCertificates decrypts every TLS field in a TlsCertificates block.
func decryptTLSCertificates(t *TlsCertificates) error {
	if err := decryptTLS(&t.Default); err != nil {
		return err
	}
	for i := range t.Certificates {
		if err := decryptTLS(&t.Certificates[i]); err != nil {
			return err
		}
	}
	for i := range t.Keys {
		if err := decryptTLS(&t.Keys[i]); err != nil {
			return err
		}
	}
	clientCA, err := decryptValue(t.ClientAuth.ClientCA)
	if err != nil {
		return err
	}
	t.ClientAuth.ClientCA = clientCA
	return nil
}

// decryptTLS decrypts the certificate and key of a single TLS pair in place.
func decryptTLS(t *TLS) error {
	cert, err := decryptValue(t.Cert)
	if err != nil {
		return fmt.Errorf("certificate: %w", err)
	}
	key, err := decryptValue(t.Key)
	if err != nil {
		return fmt.Errorf("key: %w", err)
	}
	t.Cert = cert
	t.Key = key
	return nil
}
