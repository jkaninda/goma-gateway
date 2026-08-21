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

package middlewares

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func testClaims() map[string]interface{} {
	return map[string]interface{}{
		"sub":            "user-1",
		"email":          "ada@example.com",
		"email_verified": true,
		"given_name":     "Ada",
		"family_name":    "Lovelace",
		"groups":         []interface{}{"admins", "engineering"},
		"exp":            float64(1893456000),
		"resource_access": map[string]interface{}{
			"app": map[string]interface{}{"tenant": "acme"},
		},
	}
}

func TestClaimMapperHeaders(t *testing.T) {
	mapper := &ClaimMapper{Headers: map[string]string{
		"X-Auth-User":     "sub",
		"X-Auth-Email":    "email",
		"X-Auth-Verified": "email_verified",
		"X-Auth-Groups":   "groups",
		"X-Auth-Tenant":   "resource_access.app.tenant",
		"X-Auth-Name":     "{{ .given_name }} {{ .family_name }}",
		"X-Auth-Expiry":   "exp",
		"X-Auth-Missing":  "does_not_exist",
	}}

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	mapper.Apply(request, testClaims())

	expected := map[string]string{
		"X-Auth-User":     "user-1",
		"X-Auth-Email":    "ada@example.com",
		"X-Auth-Verified": "true",
		"X-Auth-Groups":   "admins,engineering",
		"X-Auth-Tenant":   "acme",
		"X-Auth-Name":     "Ada Lovelace",
		"X-Auth-Expiry":   "1893456000",
	}
	for header, want := range expected {
		if got := request.Header.Get(header); got != want {
			t.Errorf("%s = %q, want %q", header, got, want)
		}
	}
	if got := request.Header.Get("X-Auth-Missing"); got != "" {
		t.Errorf("missing claim forwarded as %q, want no header", got)
	}
}

// A client must never be able to supply its own identity headers.
func TestClaimMapperStripsInboundHeaders(t *testing.T) {
	mapper := &ClaimMapper{Headers: map[string]string{
		"X-Auth-Email": "email",
		"X-Auth-Role":  "role", // Not present in the claims.
	}}

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("X-Auth-Email", "attacker@example.com")
	request.Header.Set("X-Auth-Role", "admin")
	request.Header.Set("X-Auth-Email-Encoding", "base64")
	mapper.Apply(request, testClaims())

	if got := request.Header.Get("X-Auth-Email"); got != "ada@example.com" {
		t.Errorf("X-Auth-Email = %q, want the verified claim", got)
	}
	if got := request.Header.Get("X-Auth-Role"); got != "" {
		t.Errorf("X-Auth-Role = %q, want the client value to be stripped", got)
	}
	if got := request.Header.Get("X-Auth-Email-Encoding"); got != "" {
		t.Errorf("X-Auth-Email-Encoding = %q, want the client value to be stripped", got)
	}
}

func TestClaimMapperStripsInboundQueryAndCookies(t *testing.T) {
	mapper := &ClaimMapper{
		Query:   map[string]string{"uid": "sub"},
		Cookies: map[string]string{"app_user": "email", "app_role": "role"},
	}

	request := httptest.NewRequest(http.MethodGet, "/api?uid=attacker&page=2", nil)
	request.AddCookie(&http.Cookie{Name: "app_user", Value: "attacker"})
	request.AddCookie(&http.Cookie{Name: "app_role", Value: "admin"})
	request.AddCookie(&http.Cookie{Name: "session", Value: "keep-me"})
	mapper.Apply(request, testClaims())

	query := request.URL.Query()
	if got := query.Get("uid"); got != "user-1" {
		t.Errorf("uid = %q, want the verified claim", got)
	}
	if got := query.Get("page"); got != "2" {
		t.Errorf("page = %q, want unrelated query parameters preserved", got)
	}

	cookies := map[string]string{}
	for _, cookie := range request.Cookies() {
		cookies[cookie.Name] = cookie.Value
	}
	if cookies["app_user"] != "ada%40example.com" {
		t.Errorf("app_user cookie = %q, want the verified claim", cookies["app_user"])
	}
	if _, present := cookies["app_role"]; present {
		t.Errorf("app_role cookie = %q, want the client value to be stripped", cookies["app_role"])
	}
	if cookies["session"] != "keep-me" {
		t.Errorf("session cookie = %q, want unrelated cookies preserved", cookies["session"])
	}
}

// A claim an identity provider lets users set themselves must not be able to
// inject a second header into the proxied request.
func TestClaimMapperRejectsHeaderInjection(t *testing.T) {
	mapper := &ClaimMapper{Headers: map[string]string{"X-Auth-Name": "name"}}
	claims := map[string]interface{}{"name": "Ada\r\nX-Auth-Role: admin"}

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	mapper.Apply(request, claims)

	value := request.Header.Get("X-Auth-Name")
	if strings.ContainsAny(value, "\r\n") {
		t.Fatalf("X-Auth-Name = %q, want control characters removed", value)
	}
	if got := request.Header.Get("X-Auth-Role"); got != "" {
		t.Errorf("X-Auth-Role = %q, want no injected header", got)
	}
}

func TestClaimMapperEncodesNonASCII(t *testing.T) {
	mapper := &ClaimMapper{Headers: map[string]string{"X-Auth-Name": "name"}}
	claims := map[string]interface{}{"name": "Jönas Kaninda"}

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	mapper.Apply(request, claims)

	want := base64.StdEncoding.EncodeToString([]byte("Jönas Kaninda"))
	if got := request.Header.Get("X-Auth-Name"); got != want {
		t.Errorf("X-Auth-Name = %q, want %q", got, want)
	}
	if got := request.Header.Get("X-Auth-Name-Encoding"); got != "base64" {
		t.Errorf("X-Auth-Name-Encoding = %q, want base64", got)
	}

	raw := &ClaimMapper{Headers: map[string]string{"X-Auth-Name": "name"}, Encoding: ClaimEncodingRaw}
	request = httptest.NewRequest(http.MethodGet, "/", nil)
	raw.Apply(request, claims)
	if got := request.Header.Get("X-Auth-Name"); got != "Jönas Kaninda" {
		t.Errorf("raw encoding: X-Auth-Name = %q, want the value unchanged", got)
	}
}

func TestClaimMapperBoundsValueSize(t *testing.T) {
	mapper := &ClaimMapper{
		Headers:       map[string]string{"X-Auth-Groups": "groups"},
		MaxValueBytes: 8,
	}
	claims := map[string]interface{}{"groups": []interface{}{"a-very-long-group-name", "another-one"}}

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("X-Auth-Groups", "spoofed")
	mapper.Apply(request, claims)

	if got := request.Header.Get("X-Auth-Groups"); got != "" {
		t.Errorf("X-Auth-Groups = %q, want oversized value dropped and inbound value stripped", got)
	}
}

func TestClaimMapperForwardTokens(t *testing.T) {
	mapper := &ClaimMapper{AccessTokenHeader: "Authorization", IDTokenHeader: "X-Auth-Id-Token"}

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("Authorization", "Bearer forged")
	request.Header.Set("X-Auth-Id-Token", "forged")
	mapper.Strip(request)
	mapper.ForwardTokens(request, "access-token", "id-token")

	if got := request.Header.Get("Authorization"); got != "Bearer access-token" {
		t.Errorf("Authorization = %q, want the session's access token", got)
	}
	if got := request.Header.Get("X-Auth-Id-Token"); got != "id-token" {
		t.Errorf("X-Auth-Id-Token = %q, want the session's ID token", got)
	}
}

func TestClaimMapperCustomArraySeparator(t *testing.T) {
	mapper := &ClaimMapper{
		Headers:        map[string]string{"X-Auth-Groups": "groups"},
		ArraySeparator: "|",
	}
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	mapper.Apply(request, testClaims())

	if got := request.Header.Get("X-Auth-Groups"); got != "admins|engineering" {
		t.Errorf("X-Auth-Groups = %q, want admins|engineering", got)
	}
}

func TestClaimMapperDisabled(t *testing.T) {
	var mapper *ClaimMapper
	if mapper.Enabled() {
		t.Fatal("nil mapper reported as enabled")
	}
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("X-Auth-Email", "attacker@example.com")
	// A nil mapper must be inert, not panic.
	mapper.Apply(request, testClaims())
	mapper.Strip(request)
	mapper.ForwardTokens(request, "a", "b")
}

func TestFormatClaimValue(t *testing.T) {
	tests := []struct {
		name  string
		value interface{}
		want  string
	}{
		{"string", "value", "value"},
		{"bool", true, "true"},
		{"integral float", float64(42), "42"},
		{"fractional float", 4.5, "4.5"},
		{"nil", nil, ""},
		{"string slice", []string{"a", "b"}, "a,b"},
		{"object", map[string]interface{}{"tenant": "acme"}, `{"tenant":"acme"}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := FormatClaimValue(test.value, DefaultArraySeparator); got != test.want {
				t.Errorf("FormatClaimValue(%v) = %q, want %q", test.value, got, test.want)
			}
		})
	}
}

func TestExtractClaim(t *testing.T) {
	claims := testClaims()

	if value, err := ExtractClaim(claims, "resource_access.app.tenant"); err != nil || value != "acme" {
		t.Errorf("ExtractClaim(nested) = %v, %v; want acme, nil", value, err)
	}
	if _, err := ExtractClaim(claims, "resource_access.missing.tenant"); err == nil {
		t.Error("ExtractClaim(missing) = nil error, want an error")
	}
	if _, err := ExtractClaim(claims, "email.nested"); err == nil {
		t.Error("ExtractClaim(through a scalar) = nil error, want an error")
	}
	if _, err := ExtractClaim(claims, ""); err == nil {
		t.Error("ExtractClaim(empty path) = nil error, want an error")
	}
}
