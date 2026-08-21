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

	goutils "github.com/jkaninda/go-utils"
	"gopkg.in/yaml.v3"
)

// decodeOauthRule walks the same path the gateway takes at load time: YAML into
// a generic rule, then a deep copy into the typed rule.
func decodeOauthRule(t *testing.T, source string) *OauthRulerMiddleware {
	t.Helper()
	middleware := &Middleware{}
	if err := yaml.Unmarshal([]byte(source), middleware); err != nil {
		t.Fatalf("failed to decode middleware: %v", err)
	}
	rule := &OauthRulerMiddleware{}
	if err := goutils.DeepCopy(rule, middleware.Rule); err != nil {
		t.Fatalf("failed to copy rule: %v", err)
	}
	return rule
}

func TestOauthRuleForwardDecoding(t *testing.T) {
	rule := decodeOauthRule(t, `
name: sso
type: oauth
paths: ["/*"]
rule:
  clientId: goma
  clientSecret: secret
  provider: custom
  redirectUrl: https://example.com/callback
  endpoint:
    authUrl: https://idp.example.com/authorize
    tokenUrl: https://idp.example.com/token
    jwksUrl: https://idp.example.com/jwks
  issuer: https://idp.example.com
  audience: goma
  claimsSource: [id_token, userinfo]
  forward:
    stripInbound: true
    arraySeparator: "|"
    encoding: raw
    maxValueBytes: 2048
    accessTokenHeader: Authorization
    idTokenHeader: X-Auth-Id-Token
    headers:
      X-Auth-User: sub
      X-Auth-Name: "{{ .given_name }} {{ .family_name }}"
    query:
      uid: sub
    cookies:
      app_user: email
`)

	if err := rule.validate(); err != nil {
		t.Fatalf("validate() = %v, want nil", err)
	}
	if rule.Issuer != "https://idp.example.com" || rule.Audience != "goma" {
		t.Errorf("issuer/audience = %q/%q, want the configured values", rule.Issuer, rule.Audience)
	}
	if len(rule.ClaimsSource) != 2 {
		t.Fatalf("claimsSource = %v, want two entries", rule.ClaimsSource)
	}

	mapper := claimMapper(rule.Forward, nil)
	if mapper == nil {
		t.Fatal("claimMapper() = nil, want a mapper")
	}
	if got := mapper.Headers["X-Auth-Name"]; got != "{{ .given_name }} {{ .family_name }}" {
		t.Errorf("X-Auth-Name mapping = %q, want the template", got)
	}
	if got := mapper.Query["uid"]; got != "sub" {
		t.Errorf("uid mapping = %q, want sub", got)
	}
	if got := mapper.Cookies["app_user"]; got != "email" {
		t.Errorf("app_user mapping = %q, want email", got)
	}
	if mapper.ArraySeparator != "|" || mapper.Encoding != "raw" || mapper.MaxValueBytes != 2048 {
		t.Errorf("mapper options = %q/%q/%d, want |/raw/2048",
			mapper.ArraySeparator, mapper.Encoding, mapper.MaxValueBytes)
	}
	if mapper.AccessTokenHeader != "Authorization" || mapper.IDTokenHeader != "X-Auth-Id-Token" {
		t.Errorf("token headers = %q/%q, want Authorization/X-Auth-Id-Token",
			mapper.AccessTokenHeader, mapper.IDTokenHeader)
	}
	if mapper.StripInbound == nil || !*mapper.StripInbound {
		t.Error("stripInbound did not survive decoding")
	}
}

// A route the gateway cannot verify tokens for must not load at all.
func TestOauthRuleRequiresVerifier(t *testing.T) {
	rule := decodeOauthRule(t, `
name: sso
type: oauth
paths: ["/*"]
rule:
  clientId: goma
  clientSecret: secret
  provider: custom
  redirectUrl: https://example.com/callback
  endpoint:
    authUrl: https://idp.example.com/authorize
    tokenUrl: https://idp.example.com/token
`)
	if err := rule.validate(); err == nil {
		t.Error("validate() = nil, want an error for a rule with no jwksUrl and no userInfoUrl")
	}
}

// Known providers do not need their endpoints spelled out.
func TestOauthRuleProviderDefaults(t *testing.T) {
	for provider, wantUserInfo := range map[string]string{
		"google":   "https://www.googleapis.com/oauth2/v2/userinfo",
		"github":   "https://api.github.com/user",
		"gitlab":   "https://gitlab.com/oauth/userinfo",
		"amazon":   "https://api.amazon.com/user/profile",
		"facebook": "https://graph.facebook.com/me?fields=id,name,email",
	} {
		t.Run(provider, func(t *testing.T) {
			rule := &OauthRulerMiddleware{
				ClientID:     "goma",
				ClientSecret: "secret",
				RedirectURL:  "https://example.com/callback",
				Provider:     provider,
			}
			if err := rule.validate(); err != nil {
				t.Fatalf("validate() = %v, want nil", err)
			}
			if rule.Endpoint.UserInfoURL != wantUserInfo {
				t.Errorf("userInfoUrl = %q, want %q", rule.Endpoint.UserInfoURL, wantUserInfo)
			}
		})
	}
}

func TestOauthRuleRejectsUnknownClaimsSource(t *testing.T) {
	rule := &OauthRulerMiddleware{
		ClientID:     "goma",
		ClientSecret: "secret",
		RedirectURL:  "https://example.com/callback",
		Provider:     "google",
		ClaimsSource: []string{"refresh_token"},
	}
	if err := rule.validate(); err == nil {
		t.Error("validate() = nil, want an error for an unknown claimsSource")
	}
}

// The deprecated flat map keeps working, and the nested block wins per key.
func TestJwtForwardHeadersBackwardCompatible(t *testing.T) {
	legacy := map[string]string{"X-User-ID": "sub", "X-User-Email": "email"}

	mapper := claimMapper(nil, legacy)
	if mapper == nil || mapper.Headers["X-User-ID"] != "sub" {
		t.Fatalf("claimMapper(legacy only) = %v, want the legacy headers", mapper)
	}

	mapper = claimMapper(&ForwardClaimsRule{
		Headers: map[string]string{"X-User-Email": "mail", "X-User-Name": "name"},
	}, legacy)
	if got := mapper.Headers["X-User-ID"]; got != "sub" {
		t.Errorf("X-User-ID = %q, want the legacy mapping preserved", got)
	}
	if got := mapper.Headers["X-User-Email"]; got != "mail" {
		t.Errorf("X-User-Email = %q, want the nested block to win", got)
	}
	if got := mapper.Headers["X-User-Name"]; got != "name" {
		t.Errorf("X-User-Name = %q, want the nested mapping", got)
	}
	if legacy["X-User-Email"] != "email" {
		t.Error("the legacy map was mutated")
	}

	if claimMapper(nil, nil) != nil {
		t.Error("claimMapper(nothing configured) != nil, want nil so the mapper stays inert")
	}
}
