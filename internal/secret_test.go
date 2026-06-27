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
	"testing"

	"github.com/jkaninda/encryptor"
)

const testPassphrase = "test-passphrase"

func TestDecryptConfigMiddlewareAndTLS(t *testing.T) {
	t.Setenv(EncryptionKeyEnv, testPassphrase)

	ruleYAML := "realm: Restricted\nusers:\n  - admin:secret\n"
	encRule, err := encryptor.EncryptString([]byte(ruleYAML), testPassphrase)
	if err != nil {
		t.Fatal(err)
	}
	encCert, err := encryptor.EncryptString([]byte("CERT-PEM"), testPassphrase)
	if err != nil {
		t.Fatal(err)
	}
	encKey, err := encryptor.EncryptString([]byte("KEY-PEM"), testPassphrase)
	if err != nil {
		t.Fatal(err)
	}

	g := &Goma{
		gateway: &Gateway{
			TLS: TlsCertificates{Default: TLS{Cert: encCert, Key: encKey}},
		},
		dynamicRoutes: []Route{
			{Name: "r1", TLS: TlsCertificate{Certificate: TLS{Cert: encCert, Key: encKey}}},
		},
		dynamicMiddlewares: []Middleware{
			{Name: "auth", Type: BasicAuth, Rule: encRule},
			{Name: "plain", Type: "rateLimit", Rule: map[string]interface{}{"unit": "minute"}},
		},
	}

	if err := g.decryptConfig(); err != nil {
		t.Fatalf("decryptConfig: %v", err)
	}

	// Gateway + route TLS decrypted in place.
	if g.gateway.TLS.Default.Cert != "CERT-PEM" || g.gateway.TLS.Default.Key != "KEY-PEM" {
		t.Fatalf("gateway TLS not decrypted: %+v", g.gateway.TLS.Default)
	}
	if g.dynamicRoutes[0].TLS.Certificate.Cert != "CERT-PEM" {
		t.Fatalf("route TLS not decrypted: %+v", g.dynamicRoutes[0].TLS.Certificate)
	}

	// Encrypted basic-auth rule decoded into the typed structure.
	rule, ok := g.dynamicMiddlewares[0].Rule.(BasicRuleMiddleware)
	if !ok {
		t.Fatalf("expected BasicRuleMiddleware, got %T", g.dynamicMiddlewares[0].Rule)
	}
	if rule.Realm != "Restricted" || len(rule.Users) != 1 {
		t.Fatalf("unexpected decoded rule: %+v", rule)
	}

	// Plain (unencrypted) rule untouched.
	if _, ok := g.dynamicMiddlewares[1].Rule.(map[string]interface{}); !ok {
		t.Fatalf("plain rule should be untouched, got %T", g.dynamicMiddlewares[1].Rule)
	}
}

func TestDecryptConfigMissingPassphrase(t *testing.T) {
	t.Setenv(EncryptionKeyEnv, "")

	enc, err := encryptor.EncryptString([]byte("data"), testPassphrase)
	if err != nil {
		t.Fatal(err)
	}
	g := &Goma{
		gateway:       &Gateway{},
		dynamicRoutes: []Route{{Name: "r1", TLS: TlsCertificate{Certificate: TLS{Cert: enc}}}},
	}
	if err := g.decryptConfig(); err == nil {
		t.Fatal("expected error when encrypted value present but passphrase unset")
	}
}

func TestDecryptValuePlaintextPassthrough(t *testing.T) {
	t.Setenv(EncryptionKeyEnv, testPassphrase)
	got, err := decryptValue("plain-text")
	if err != nil {
		t.Fatal(err)
	}
	if got != "plain-text" {
		t.Fatalf("expected passthrough, got %q", got)
	}
}
