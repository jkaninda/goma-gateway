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
	"net/http"
	"strings"
	"testing"
	"time"

	goutils "github.com/jkaninda/go-utils"
	"github.com/jkaninda/goma-gateway/internal/middlewares"
	"github.com/jkaninda/goma-gateway/util"
	"gopkg.in/yaml.v3"
)

const (
	testClientID = "goma"
	claimSub     = "sub"
	claimEmail   = "email"
	testSecret   = "secret"

	testCallbackPath = "/oauth2/callback"
	testRoutePath    = "/protected"
)

// decodeOauthRule walks the same path the gateway takes at load time: YAML into
// a generic rule, then a deep copy into the typed rule.
func decodeOIDCRule(t *testing.T, source string) *OIDCRuleMiddleware {
	t.Helper()
	middleware := &Middleware{}
	if err := yaml.Unmarshal([]byte(source), middleware); err != nil {
		t.Fatalf("failed to decode middleware: %v", err)
	}
	rule := &OIDCRuleMiddleware{}
	if err := goutils.DeepCopy(rule, middleware.Rule); err != nil {
		t.Fatalf("failed to copy rule: %v", err)
	}
	return rule
}

func TestOIDCRuleForwardDecoding(t *testing.T) {
	rule := decodeOIDCRule(t, `
name: sso
type: oauth
paths: ["/.*"]
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
	if rule.Issuer != "https://idp.example.com" || rule.Audience != testClientID {
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
	if got := mapper.Query["uid"]; got != claimSub {
		t.Errorf("uid mapping = %q, want sub", got)
	}
	if got := mapper.Cookies["app_user"]; got != claimEmail {
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
func TestOIDCRuleRequiresVerifier(t *testing.T) {
	rule := decodeOIDCRule(t, `
name: sso
type: oauth
paths: ["/.*"]
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
func TestOIDCRuleProviderDefaults(t *testing.T) {
	for provider, wantUserInfo := range map[string]string{
		middlewares.ProviderGoogle:   "https://www.googleapis.com/oauth2/v2/userinfo",
		middlewares.ProviderGitHub:   "https://api.github.com/user",
		middlewares.ProviderGitLab:   "https://gitlab.com/oauth/userinfo",
		middlewares.ProviderAmazon:   "https://api.amazon.com/user/profile",
		middlewares.ProviderFacebook: "https://graph.facebook.com/me?fields=id,name,email",
	} {
		t.Run(provider, func(t *testing.T) {
			rule := &OIDCRuleMiddleware{
				ClientID:     testClientID,
				ClientSecret: testSecret,
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

func TestOIDCRuleRejectsUnknownClaimsSource(t *testing.T) {
	rule := &OIDCRuleMiddleware{
		ClientID:     testClientID,
		ClientSecret: testSecret,
		RedirectURL:  "https://example.com/callback",
		Provider:     middlewares.ProviderGoogle,
		ClaimsSource: []string{"refresh_token"},
	}
	if err := rule.validate(); err == nil {
		t.Error("validate() = nil, want an error for an unknown claimsSource")
	}
}

// The deprecated flat map keeps working, and the nested block wins per key.
func TestJwtForwardHeadersBackwardCompatible(t *testing.T) {
	legacy := map[string]string{"X-User-ID": claimSub, "X-User-Email": claimEmail}

	mapper := claimMapper(nil, legacy)
	if mapper == nil || mapper.Headers["X-User-ID"] != claimSub {
		t.Fatalf("claimMapper(legacy only) = %v, want the legacy headers", mapper)
	}

	mapper = claimMapper(&ForwardClaimsRule{
		Headers: map[string]string{"X-User-Email": "mail", "X-User-Name": "name"},
	}, legacy)
	if got := mapper.Headers["X-User-ID"]; got != claimSub {
		t.Errorf("X-User-ID = %q, want the legacy mapping preserved", got)
	}
	if got := mapper.Headers["X-User-Email"]; got != "mail" {
		t.Errorf("X-User-Email = %q, want the nested block to win", got)
	}
	if got := mapper.Headers["X-User-Name"]; got != "name" {
		t.Errorf("X-User-Name = %q, want the nested mapping", got)
	}
	if legacy["X-User-Email"] != claimEmail {
		t.Error("the legacy map was mutated")
	}

	if claimMapper(nil, nil) != nil {
		t.Error("claimMapper(nothing configured) != nil, want nil so the mapper stays inert")
	}
}

// The new configuration decodes end to end, including the session block.
func TestOIDCRuleSessionDecoding(t *testing.T) {
	rule := decodeOIDCRule(t, `
name: sso
type: oidc
paths: ["/.*"]
rule:
  clientId: goma
  clientSecret: secret
  issuer: https://idp.example.com/application/o/goma/
  callbackPath: /oauth2/callback
  logoutPath: /oauth2/logout
  postLoginRedirect: /dashboard
  postLogoutRedirect: /bye
  pkce: false
  claimsExpression: "Contains('groups', 'admins')"
  session:
    store: memory
    secret: session-secret
    ttl: 8h
    idleTimeout: 30m
    cookie:
      name: app_session
      path: /
      sameSite: strict
`)

	if err := rule.validate(); err != nil {
		t.Fatalf("validate() = %v, want nil", err)
	}
	if rule.CallbackPath != testCallbackPath || rule.LogoutPath != "/oauth2/logout" {
		t.Errorf("callback/logout = %q/%q, want the configured paths", rule.CallbackPath, rule.LogoutPath)
	}
	if rule.PKCE == nil || *rule.PKCE {
		t.Error("pkce: false did not survive decoding")
	}
	if rule.Session == nil || rule.Session.Store != middlewares.SessionStoreMemory {
		t.Fatalf("session = %+v, want the memory store", rule.Session)
	}

	options := sessionOptions(rule.Session, "/app")
	if options.TTL != 8*time.Hour || options.IdleTimeout != 30*time.Minute {
		t.Errorf("ttl/idleTimeout = %v/%v, want 8h/30m", options.TTL, options.IdleTimeout)
	}
	if options.CookieName != "app_session" || options.CookiePath != "/" {
		t.Errorf("cookie = %q at %q, want app_session at /", options.CookieName, options.CookiePath)
	}
	if options.SameSite != http.SameSiteStrictMode {
		t.Errorf("sameSite = %v, want strict", options.SameSite)
	}
}

// Without a session block the cookie is scoped to the route, so two routes on
// one host do not share a session.
func TestOIDCSessionDefaultsToRouteScope(t *testing.T) {
	options := sessionOptions(nil, "/app")
	if options.CookiePath != "/app" {
		t.Errorf("cookie path = %q, want the route path", options.CookiePath)
	}
	if options.Store != "" {
		t.Errorf("store = %q, want the cookie store default", options.Store)
	}
}

// A config written for the old middleware keeps working, moved onto the fields
// that replaced it.
func TestOIDCRuleMigratesDeprecatedFields(t *testing.T) {
	rule := decodeOIDCRule(t, `
name: sso
type: oauth
paths: ["/.*"]
rule:
  clientId: goma
  clientSecret: secret
  provider: google
  redirectUrl: https://example.com/callback/protected
  redirectPath: /dashboard
  cookiePath: /protected
  state: randomStateString
`)

	if err := rule.validate(); err != nil {
		t.Fatalf("validate() = %v, want nil", err)
	}
	if rule.CallbackPath != "/callback/protected" {
		t.Errorf("callbackPath = %q, want it derived from redirectUrl", rule.CallbackPath)
	}
	if rule.PostLoginRedirect != "/dashboard" {
		t.Errorf("postLoginRedirect = %q, want it taken from redirectPath", rule.PostLoginRedirect)
	}
	if rule.Session == nil || rule.Session.Cookie.Path != testRoutePath {
		t.Errorf("session cookie path = %+v, want it taken from cookiePath", rule.Session)
	}
}

func TestOIDCRuleRejectsBadSession(t *testing.T) {
	base := func() *OIDCRuleMiddleware {
		return &OIDCRuleMiddleware{
			ClientID: testClientID, ClientSecret: testSecret,
			Provider: middlewares.ProviderGoogle,
		}
	}

	tests := map[string]*OIDCSessionRule{
		"unknown store":    {Store: "postgres"},
		"invalid ttl":      {TTL: "forever"},
		"invalid idle":     {IdleTimeout: "10 minutes"},
		"unknown sameSite": {Cookie: OIDCCookieRule{SameSite: "none-ish"}},
	}
	for name, session := range tests {
		t.Run(name, func(t *testing.T) {
			rule := base()
			rule.Session = session
			if err := rule.validate(); err == nil {
				t.Errorf("validate() = nil, want an error for %s", name)
			}
		})
	}
}

// An issuer alone is enough: discovery supplies the endpoints and the keys.
func TestOIDCRuleAcceptsIssuerOnly(t *testing.T) {
	rule := &OIDCRuleMiddleware{
		ClientID: testClientID, ClientSecret: testSecret, Issuer: "https://idp.example.com",
	}
	if err := rule.validate(); err != nil {
		t.Errorf("validate() = %v, want nil", err)
	}
}

// The route's group joins its own prefix onto whatever pattern it is given, so
// an absolute callback path has to be translated before it is registered.
func TestGroupPattern(t *testing.T) {
	tests := []struct {
		routePath string
		absolute  string
		want      string
		ok        bool
	}{
		{testRoutePath, testRoutePath + testCallbackPath, testCallbackPath, true},
		{testRoutePath + "/", testRoutePath + testCallbackPath, testCallbackPath, true},
		{testRoutePath, testRoutePath, "/", true},
		{"/", testCallbackPath, testCallbackPath, true},
		{"", testCallbackPath, testCallbackPath, true},
		// Outside the route's group, so it cannot be registered on it.
		{testRoutePath, testCallbackPath, "", false},
		{testRoutePath, testRoutePath + "-other/callback", "", false},
	}

	for _, test := range tests {
		t.Run(test.routePath+" "+test.absolute, func(t *testing.T) {
			got, ok := groupPattern(test.routePath, test.absolute)
			if ok != test.ok {
				t.Fatalf("groupPattern(%q, %q) ok = %v, want %v", test.routePath, test.absolute, ok, test.ok)
			}
			if got != test.want {
				t.Errorf("groupPattern(%q, %q) = %q, want %q", test.routePath, test.absolute, got, test.want)
			}
		})
	}
}

// The default callback lives under the route, so it is reachable and the
// session cookie is sent to it.
func TestOIDCDefaultCallbackIsUnderTheRoute(t *testing.T) {
	routePath := testRoutePath
	callbackPath := util.ParseURLPath(routePath + testCallbackPath)

	if _, ok := groupPattern(routePath, callbackPath); !ok {
		t.Fatalf("the default callback %q cannot be registered on route %q", callbackPath, routePath)
	}
	options := sessionOptions(nil, routePath)
	if !strings.HasPrefix(callbackPath, options.CookiePath) {
		t.Errorf("the default callback %q is outside the session cookie path %q", callbackPath, options.CookiePath)
	}
}
