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
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

func signedBundle(t *testing.T, key ed25519.PrivateKey) *ConfigBundle {
	t.Helper()
	bundle := &ConfigBundle{
		Version: "1",
		Routes:  []Route{{Name: "api", Path: "/api", Target: "https://api.example.com"}},
	}
	bundle.Signature = base64.StdEncoding.EncodeToString(
		ed25519.Sign(key, []byte(bundle.CalculateChecksum())))
	return bundle
}

func TestVerifyBundleRejectsTamperingAndForgery(t *testing.T) {
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	signing := &BundleSigning{PublicKey: base64.StdEncoding.EncodeToString(public)}

	t.Run("a correctly signed bundle is accepted", func(t *testing.T) {
		if err := signing.verifyBundle(signedBundle(t, private)); err != nil {
			t.Fatalf("signed bundle rejected: %v", err)
		}
	})

	t.Run("an unsigned bundle is refused", func(t *testing.T) {
		bundle := signedBundle(t, private)
		bundle.Signature = ""
		if err := signing.verifyBundle(bundle); err == nil {
			t.Fatal("unsigned bundle accepted")
		}
	})

	t.Run("a route added after signing is refused", func(t *testing.T) {
		bundle := signedBundle(t, private)
		// The shadowing attack the audit describes: a longer path sorts ahead
		// of the real route and intercepts its traffic.
		bundle.Routes = append(bundle.Routes, Route{
			Name: "shadow", Path: "/api/v1/users", Target: "https://attacker.example",
		})
		if err := signing.verifyBundle(bundle); err == nil {
			t.Fatal("tampered bundle accepted")
		}
	})

	t.Run("a bundle signed by another key is refused", func(t *testing.T) {
		_, other, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := signing.verifyBundle(signedBundle(t, other)); err == nil {
			t.Fatal("bundle signed by an untrusted key accepted")
		}
	})

	t.Run("a locally recomputed checksum authenticates nothing", func(t *testing.T) {
		// An attacker controlling the bytes controls the checksum too, which is
		// why the checksum alone was never an integrity check.
		bundle := signedBundle(t, private)
		bundle.Routes[0].Target = "https://attacker.example"
		bundle.Checksum = bundle.CalculateChecksum()
		if err := signing.verifyBundle(bundle); err == nil {
			t.Fatal("bundle with a recomputed checksum accepted")
		}
	})
}

func TestSigningDisabledAcceptsUnsignedBundles(t *testing.T) {
	// Enabling signing must be a deliberate step, not a breaking upgrade.
	var signing *BundleSigning
	if err := signing.verifyBundle(&ConfigBundle{Version: "1"}); err != nil {
		t.Fatalf("unconfigured signing rejected a bundle: %v", err)
	}
}

func TestSignBundleFileRoundTrip(t *testing.T) {
	public, private, err := GenerateBundleSigningKey()
	if err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(t.TempDir(), "bundle.yml")
	if err := os.WriteFile(path, []byte("version: \"1\"\nroutes: []\nmiddlewares: []\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := SignBundleFile(path, private); err != nil {
		t.Fatal(err)
	}

	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	bundle := &ConfigBundle{}
	if err := yaml.Unmarshal(contents, bundle); err != nil {
		t.Fatal(err)
	}

	if err := (&BundleSigning{PublicKey: public}).verifyBundle(bundle); err != nil {
		t.Fatalf("a bundle signed by `goma config sign` did not verify: %v", err)
	}
}

func TestPublicKeyFileSupportsRotation(t *testing.T) {
	oldPublic, _, err := GenerateBundleSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	newPublic, newPrivate, err := GenerateBundleSigningKey()
	if err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(t.TempDir(), "keys")
	contents := "# trusted signers\n" + oldPublic + "\n" + newPublic + "\n"
	if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}

	raw, err := base64.StdEncoding.DecodeString(newPrivate)
	if err != nil {
		t.Fatal(err)
	}
	if err := (&BundleSigning{PublicKeyFile: path}).verifyBundle(signedBundle(t, raw)); err != nil {
		t.Fatalf("a bundle signed by the second listed key was rejected: %v", err)
	}
}
