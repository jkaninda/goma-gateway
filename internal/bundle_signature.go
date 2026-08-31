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
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	goutils "github.com/jkaninda/go-utils"
	"gopkg.in/yaml.v3"
)

// Provider bundles arrive over the network and are merged straight into the
// live gateway: their routes are appended and sorted longest-path-first, so a
// bundle carrying a longer path shadows a real route and intercepts its traffic
// under the gateway's own TLS.
//
// Until now nothing authenticated them. ConfigBundle.Validate checked only that
// Version was non-empty, and the HTTP provider's Checksum is recomputed locally
// from the bytes just received — it detects corruption, not forgery, and an
// attacker who controls the bytes controls the checksum too.
//
// A detached Ed25519 signature over the bundle's canonical checksum closes
// that. It is opt-in — configuring a public key is what turns enforcement on —
// but once configured, an unsigned or badly signed bundle is refused rather
// than applied.

// BundleSigning configures how provider bundles are authenticated.
type BundleSigning struct {
	// PublicKey is a base64-encoded Ed25519 public key. Takes precedence over
	// PublicKeyFile.
	PublicKey string `yaml:"publicKey,omitempty" json:"publicKey,omitempty"`
	// PublicKeyFile is a file holding the same, one key per line. Several keys
	// allow a signing key to be rotated without a flag day.
	PublicKeyFile string `yaml:"publicKeyFile,omitempty" json:"publicKeyFile,omitempty"`
}

// enabled reports whether signature verification is configured.
func (s *BundleSigning) enabled() bool {
	if s == nil {
		return false
	}
	return strings.TrimSpace(s.PublicKey) != "" || strings.TrimSpace(s.PublicKeyFile) != ""
}

// publicKeys resolves the configured trust anchors.
func (s *BundleSigning) publicKeys() ([]ed25519.PublicKey, error) {
	var encoded []string
	if inline := strings.TrimSpace(goutils.ReplaceEnvVars(s.PublicKey)); inline != "" {
		encoded = append(encoded, inline)
	}
	if path := strings.TrimSpace(goutils.ReplaceEnvVars(s.PublicKeyFile)); path != "" {
		contents, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("failed to read providers.signing.publicKeyFile: %w", err)
		}
		for _, line := range strings.Split(string(contents), "\n") {
			if line = strings.TrimSpace(line); line != "" && !strings.HasPrefix(line, "#") {
				encoded = append(encoded, line)
			}
		}
	}

	keys := make([]ed25519.PublicKey, 0, len(encoded))
	for _, value := range encoded {
		raw, err := base64.StdEncoding.DecodeString(value)
		if err != nil {
			return nil, fmt.Errorf("invalid base64 in providers.signing public key: %w", err)
		}
		if len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("providers.signing public key is %d bytes, expected %d", len(raw), ed25519.PublicKeySize)
		}
		keys = append(keys, raw)
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("providers.signing is configured but no usable public key was found")
	}
	return keys, nil
}

// verifyBundle checks the bundle's detached signature against the configured
// keys. A bundle from an unconfigured gateway is accepted with a warning, so
// enabling signing is a deliberate step rather than a breaking upgrade.
func (s *BundleSigning) verifyBundle(bundle *ConfigBundle) error {
	if !s.enabled() {
		logger.Warn("Provider bundle applied without signature verification",
			"hint", "set providers.signing.publicKey to require signed bundles")
		return nil
	}

	keys, err := s.publicKeys()
	if err != nil {
		return err
	}

	signature, err := base64.StdEncoding.DecodeString(strings.TrimSpace(bundle.Signature))
	if err != nil || len(signature) != ed25519.SignatureSize {
		return fmt.Errorf("provider bundle has no valid signature; refusing to apply it")
	}

	message := []byte(bundle.CalculateChecksum())
	for _, key := range keys {
		if ed25519.Verify(key, message, signature) {
			return nil
		}
	}
	return fmt.Errorf("provider bundle signature does not verify against any configured public key; refusing to apply it")
}

// GenerateBundleSigningKey mints an Ed25519 keypair for signing bundles,
// returning both halves base64-encoded.
func GenerateBundleSigningKey() (publicKey string, privateKey string, err error) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(public),
		base64.StdEncoding.EncodeToString(private), nil
}

// SignBundleFile signs the config bundle at path in place, writing the
// signature into its `signature` field.
func SignBundleFile(path, encodedPrivateKey string) error {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encodedPrivateKey))
	if err != nil {
		return fmt.Errorf("invalid base64 private key: %w", err)
	}
	if len(raw) != ed25519.PrivateKeySize {
		return fmt.Errorf("private key is %d bytes, expected %d", len(raw), ed25519.PrivateKeySize)
	}

	contents, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	bundle := &ConfigBundle{}
	if err := yaml.Unmarshal(contents, bundle); err != nil {
		return fmt.Errorf("failed to parse %s: %w", path, err)
	}

	// Signed over the canonical checksum, which excludes the signature,
	// checksum and timestamp fields — so the value is stable regardless of how
	// the bundle is serialized or re-serialized.
	bundle.Signature = base64.StdEncoding.EncodeToString(
		ed25519.Sign(ed25519.PrivateKey(raw), []byte(bundle.CalculateChecksum())))

	signed, err := yaml.Marshal(bundle)
	if err != nil {
		return err
	}
	return os.WriteFile(path, signed, 0600)
}
