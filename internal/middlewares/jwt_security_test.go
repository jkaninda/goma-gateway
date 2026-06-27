/*
Copyright 2024 Jonas Kaninda

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package middlewares

import (
	"crypto/rsa"
	"slices"
	"testing"
)

const (
	algRS512  = "RS512"
	algES384  = "ES384"
	adminPath = "/admin"
)

func TestAllowedAlgorithms(t *testing.T) {
	// Asymmetric key sources must never accept HMAC (RS/HS confusion guard).
	asym := []*JwtAuth{
		{JwksUrl: "https://issuer.example/jwks"},
		{RsaKey: &rsa.PublicKey{}},
		{JwksFile: &Jwks{Keys: []Jwk{{}}}},
		{}, // no key configured → safe default
	}
	for _, j := range asym {
		got := j.allowedAlgorithms()
		if slices.Contains(got, "HS256") {
			t.Fatalf("asymmetric config must not allow HS256, got %v", got)
		}
		if !slices.Contains(got, "RS256") {
			t.Fatalf("asymmetric config should allow RS256, got %v", got)
		}
	}

	// A shared secret is an HMAC key → HMAC family only, no asymmetric algs.
	hs := (&JwtAuth{Secret: "s3cret"}).allowedAlgorithms()
	if !slices.Contains(hs, "HS256") || slices.Contains(hs, "RS256") {
		t.Fatalf("secret config should allow only HMAC, got %v", hs)
	}

	// JWKS URL takes precedence over a stray Secret, mirroring resolveKeyFunc.
	mixed := (&JwtAuth{JwksUrl: "https://issuer.example/jwks", Secret: "s"}).allowedAlgorithms()
	if slices.Contains(mixed, "HS256") {
		t.Fatalf("JWKS URL must win over Secret and exclude HMAC, got %v", mixed)
	}

	// Explicit (deprecated) Algo overrides the defaults.
	exact := (&JwtAuth{Secret: "s", Algo: algRS512}).allowedAlgorithms()
	if len(exact) != 1 || exact[0] != algRS512 {
		t.Fatalf("explicit Algo should be the only allowed method, got %v", exact)
	}

	// Explicit Algorithms list is used verbatim and wins over the deprecated Algo.
	list := (&JwtAuth{Algo: "HS256", Algorithms: []string{algRS512, algES384}}).allowedAlgorithms()
	if !slices.Equal(list, []string{algRS512, algES384}) {
		t.Fatalf("Algorithms should take precedence over Algo, got %v", list)
	}
}

func TestIsMatchingPathCaseInsensitive(t *testing.T) {
	cases := []struct {
		req, rule string
		want      bool
	}{
		{adminPath, adminPath, true},
		{"/Admin", adminPath, true}, // case bypass must not work
		{"/ADMIN", adminPath, true},
		{"/admin/users", "/admin/*", true},
		{"/Admin/Users", "/admin/*", true}, // case bypass on wildcard
		{"/public", adminPath, false},
		{"/administrator", adminPath, false}, // exact rule, not a prefix
	}
	for _, tc := range cases {
		if got := isMatchingPath(tc.req, tc.rule); got != tc.want {
			t.Fatalf("isMatchingPath(%q, %q) = %v, want %v", tc.req, tc.rule, got, tc.want)
		}
	}
}
