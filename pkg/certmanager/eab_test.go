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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-acme/lego/v4/registration"
)

func TestValidateConfig_EabPair(t *testing.T) {
	tests := []struct {
		name    string
		eab     Eab
		wantErr bool
	}{
		{name: "neither", eab: Eab{}},
		{name: "both", eab: Eab{Kid: "abc", HmacKey: "c2VjcmV0"}},
		{name: "kid only", eab: Eab{Kid: "abc"}, wantErr: true},
		{name: "hmac only", eab: Eab{HmacKey: "c2VjcmV0"}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &provider{cfg: ProviderConfig{
				Type: CertAcmeProvider,
				Acme: Acme{Email: "ops@example.com", Eab: tt.eab},
			}}
			err := p.validateConfig()
			if tt.wantErr && err == nil {
				t.Fatal("expected an error for a half-configured binding")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("validateConfig: %v", err)
			}
		})
	}
}

func TestEabCredentialChanged(t *testing.T) {
	registered := func(kid string) *LegoUser {
		return &LegoUser{Registration: &registration.Resource{URI: "https://ca/acct/1"}, eabKid: kid}
	}
	tests := []struct {
		name string
		user *LegoUser
		kid  string
		want bool
	}{
		{name: "no account yet", user: &LegoUser{eabKid: "old"}, kid: "new"},
		{name: "same credential", user: registered("abc"), kid: "abc"},
		{name: "no binding either side", user: registered(""), kid: ""},
		{name: "rotated", user: registered("abc"), kid: "def", want: true},
		{name: "binding added", user: registered(""), kid: "abc", want: true},
		{name: "binding removed", user: registered("abc"), kid: "", want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &provider{user: tt.user, cfg: ProviderConfig{Acme: Acme{Eab: Eab{Kid: tt.kid}}}}
			if got := p.eabCredentialChanged(); got != tt.want {
				t.Errorf("eabCredentialChanged() = %v, want %v", got, tt.want)
			}
		})
	}
}

// The key id has to survive a restart, otherwise every start would look like a
// rotation and register a new account.
func TestUserStorageRoundTripsEabKid(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	stored, err := saveUserToStorage(&LegoUser{Email: "ops@example.com", key: key, eabKid: "abc123"})
	if err != nil {
		t.Fatalf("saveUserToStorage: %v", err)
	}
	if stored.EabKid != "abc123" {
		t.Errorf("stored EabKid = %q, want %q", stored.EabKid, "abc123")
	}

	loaded, err := loadUserFromStorage(stored)
	if err != nil {
		t.Fatalf("loadUserFromStorage: %v", err)
	}
	if loaded.eabKid != "abc123" {
		t.Errorf("loaded eabKid = %q, want %q", loaded.eabKid, "abc123")
	}
}

// A directory that advertises externalAccountRequired should fail setup with a
// message naming the fields to set, not with the CA's error at registration.
func TestSetupLegoClient_ExternalAccountRequired(t *testing.T) {
	// lego talks to a directory over HTTPS only; GOMA_ENV=development is what
	// makes the provider skip verification of the test server's certificate.
	t.Setenv(gomaEnv, development)

	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{
			"newNonce": "%[1]s/nonce",
			"newAccount": "%[1]s/account",
			"newOrder": "%[1]s/order",
			"revokeCert": "%[1]s/revoke",
			"keyChange": "%[1]s/key-change",
			"meta": {"externalAccountRequired": true}
		}`, srv.URL)
	}))
	defer srv.Close()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	newProviderFor := func(eab Eab) *provider {
		return &provider{
			cfg:  ProviderConfig{Type: CertAcmeProvider, Acme: Acme{Email: "ops@example.com", DirectoryURL: srv.URL, Eab: eab}},
			user: &LegoUser{Email: "ops@example.com", key: key},
		}
	}

	err = newProviderFor(Eab{}).setupLegoClient()
	if err == nil {
		t.Fatal("expected setup to fail when the directory requires a binding")
	}
	if !strings.Contains(err.Error(), "acme.eab.kid") {
		t.Errorf("error should name the config fields, got: %v", err)
	}

	if err := newProviderFor(Eab{Kid: "abc", HmacKey: "c2VjcmV0"}).setupLegoClient(); err != nil {
		t.Errorf("setup with a binding configured: %v", err)
	}
}
