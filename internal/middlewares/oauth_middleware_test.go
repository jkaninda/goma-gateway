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
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// jwksServer serves a JWKS for key, so the middleware can verify tokens the
// test signs with it.
func jwksServer(t *testing.T, key *rsa.PrivateKey, kid string) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(Jwks{Keys: []Jwk{{
			Kid: kid,
			Kty: "RSA",
			N:   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
		}}})
	}))
	t.Cleanup(server.Close)
	return server
}

func signToken(t *testing.T, key *rsa.PrivateKey, kid string, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid
	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}
	return signed
}

func testRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	return key
}

// nextRecorder reports whether the request reached the upstream, and captures it.
func nextRecorder(reached *bool, captured **http.Request) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*reached = true
		*captured = r
		w.WriteHeader(http.StatusOK)
	})
}

func browserRequest(path string, cookies ...*http.Cookie) *http.Request {
	request := httptest.NewRequest(http.MethodGet, path, nil)
	request.Header.Set("Accept", "text/html,application/xhtml+xml")
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	return request
}

// A token nobody signed must not be accepted just because its "exp" is in the
// future.
func TestOauthRejectsForgedToken(t *testing.T) {
	key := testRSAKey(t)
	jwks := jwksServer(t, key, "test-key")

	attacker := testRSAKey(t)
	forged := signToken(t, attacker, "test-key", jwt.MapClaims{
		"sub": "attacker",
		"exp": time.Now().Add(time.Hour).Unix(),
	})

	oauth := &Oauth{
		Path:        "/",
		Paths:       []string{"/*"},
		Provider:    "custom",
		ClientID:    "goma",
		RedirectURL: "https://example.com/callback",
		Endpoint:    OauthEndpoint{AuthURL: "https://idp.example.com/authorize", JwksURL: jwks.URL},
	}

	reached := false
	var upstream *http.Request
	recorder := httptest.NewRecorder()
	oauth.AuthMiddleware(nextRecorder(&reached, &upstream)).ServeHTTP(recorder,
		browserRequest("/protected", &http.Cookie{Name: GomaAccessToken, Value: forged}))

	if reached {
		t.Fatal("forged token reached the upstream")
	}
	if recorder.Code != http.StatusFound {
		t.Errorf("status = %d, want %d (redirect to the provider)", recorder.Code, http.StatusFound)
	}
}

// An unsigned or alg=none token must not be accepted either.
func TestOauthRejectsUnsignedToken(t *testing.T) {
	key := testRSAKey(t)
	jwks := jwksServer(t, key, "test-key")

	unsigned, err := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{
		"sub": "attacker",
		"exp": time.Now().Add(time.Hour).Unix(),
	}).SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("failed to build unsigned token: %v", err)
	}

	oauth := &Oauth{
		Path:        "/",
		Paths:       []string{"/*"},
		Provider:    "custom",
		ClientID:    "goma",
		RedirectURL: "https://example.com/callback",
		Endpoint:    OauthEndpoint{AuthURL: "https://idp.example.com/authorize", JwksURL: jwks.URL},
	}

	reached := false
	var upstream *http.Request
	recorder := httptest.NewRecorder()
	oauth.AuthMiddleware(nextRecorder(&reached, &upstream)).ServeHTTP(recorder,
		browserRequest("/protected", &http.Cookie{Name: GomaAccessToken, Value: unsigned}))

	if reached {
		t.Fatal("unsigned token reached the upstream")
	}
}

func TestOauthAcceptsVerifiedTokenAndForwardsClaims(t *testing.T) {
	key := testRSAKey(t)
	jwks := jwksServer(t, key, "test-key")

	accessToken := signToken(t, key, "test-key", jwt.MapClaims{
		"sub":    "user-1",
		"email":  "ada@example.com",
		"groups": []string{"admins"},
		"iss":    "https://idp.example.com",
		"aud":    "goma",
		"exp":    time.Now().Add(time.Hour).Unix(),
	})

	oauth := &Oauth{
		Path:         "/",
		Paths:        []string{"/*"},
		Provider:     "custom",
		ClientID:     "goma",
		Issuer:       "https://idp.example.com",
		Audience:     "goma",
		RedirectURL:  "https://example.com/callback",
		Endpoint:     OauthEndpoint{AuthURL: "https://idp.example.com/authorize", JwksURL: jwks.URL},
		ClaimsSource: []string{ClaimSourceAccessToken},
		Forward: &ClaimMapper{Headers: map[string]string{
			"X-Auth-User":   "sub",
			"X-Auth-Email":  "email",
			"X-Auth-Groups": "groups",
		}},
	}

	reached := false
	var upstream *http.Request
	recorder := httptest.NewRecorder()
	request := browserRequest("/protected", &http.Cookie{Name: GomaAccessToken, Value: accessToken})
	request.Header.Set("X-Auth-Email", "attacker@example.com")
	oauth.AuthMiddleware(nextRecorder(&reached, &upstream)).ServeHTTP(recorder, request)

	if !reached {
		t.Fatalf("verified token did not reach the upstream, status = %d", recorder.Code)
	}
	if got := upstream.Header.Get("X-Auth-User"); got != "user-1" {
		t.Errorf("X-Auth-User = %q, want user-1", got)
	}
	if got := upstream.Header.Get("X-Auth-Email"); got != "ada@example.com" {
		t.Errorf("X-Auth-Email = %q, want the verified claim, not the client's", got)
	}
	if got := upstream.Header.Get("X-Auth-Groups"); got != "admins" {
		t.Errorf("X-Auth-Groups = %q, want admins", got)
	}
}

// A token minted for a different client of the same provider must not pass.
func TestOauthEnforcesIssuerAndAudience(t *testing.T) {
	key := testRSAKey(t)
	jwks := jwksServer(t, key, "test-key")

	otherClient := signToken(t, key, "test-key", jwt.MapClaims{
		"sub": "user-1",
		"iss": "https://idp.example.com",
		"aud": "another-app",
		"exp": time.Now().Add(time.Hour).Unix(),
	})

	oauth := &Oauth{
		Path:        "/",
		Paths:       []string{"/*"},
		Provider:    "custom",
		ClientID:    "goma",
		Issuer:      "https://idp.example.com",
		Audience:    "goma",
		RedirectURL: "https://example.com/callback",
		Endpoint:    OauthEndpoint{AuthURL: "https://idp.example.com/authorize", JwksURL: jwks.URL},
	}

	reached := false
	var upstream *http.Request
	recorder := httptest.NewRecorder()
	oauth.AuthMiddleware(nextRecorder(&reached, &upstream)).ServeHTTP(recorder,
		browserRequest("/protected", &http.Cookie{Name: GomaAccessToken, Value: otherClient}))

	if reached {
		t.Fatal("token issued to another client reached the upstream")
	}
}

// The ID token's audience is this client by definition, whatever the config says.
func TestOauthEnforcesIDTokenAudience(t *testing.T) {
	key := testRSAKey(t)
	jwks := jwksServer(t, key, "test-key")

	idToken := signToken(t, key, "test-key", jwt.MapClaims{
		"sub": "user-1",
		"aud": "another-app",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	accessToken := signToken(t, key, "test-key", jwt.MapClaims{
		"sub": "user-1",
		"exp": time.Now().Add(time.Hour).Unix(),
	})

	oauth := &Oauth{
		Path:        "/",
		Paths:       []string{"/*"},
		Provider:    "custom",
		ClientID:    "goma",
		RedirectURL: "https://example.com/callback",
		Endpoint:    OauthEndpoint{AuthURL: "https://idp.example.com/authorize", JwksURL: jwks.URL},
	}

	reached := false
	var upstream *http.Request
	recorder := httptest.NewRecorder()
	oauth.AuthMiddleware(nextRecorder(&reached, &upstream)).ServeHTTP(recorder,
		browserRequest("/protected",
			&http.Cookie{Name: GomaAccessToken, Value: accessToken},
			&http.Cookie{Name: GomaIDToken, Value: idToken}))

	if reached {
		t.Fatal("ID token issued to another client reached the upstream")
	}
}

// Opaque access tokens (Google, GitHub, Facebook) are validated by asking the
// provider's user info endpoint, which also supplies the claims to forward.
func TestOauthVerifiesOpaqueTokenWithUserInfo(t *testing.T) {
	var seenAuthorization string
	userInfo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenAuthorization = r.Header.Get("Authorization")
		if seenAuthorization != "Bearer opaque-valid-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"sub":"user-1","email":"ada@example.com"}`)
	}))
	defer userInfo.Close()

	oauth := &Oauth{
		Path:        "/",
		Paths:       []string{"/*"},
		Provider:    "custom",
		ClientID:    "goma",
		RedirectURL: "https://example.com/callback",
		Endpoint:    OauthEndpoint{AuthURL: "https://idp.example.com/authorize", UserInfoURL: userInfo.URL},
		Forward:     &ClaimMapper{Headers: map[string]string{"X-Auth-Email": "email"}},
	}

	reached := false
	var upstream *http.Request
	recorder := httptest.NewRecorder()
	oauth.AuthMiddleware(nextRecorder(&reached, &upstream)).ServeHTTP(recorder,
		browserRequest("/protected", &http.Cookie{Name: GomaAccessToken, Value: "opaque-valid-token"}))

	if !reached {
		t.Fatalf("valid opaque token did not reach the upstream, status = %d", recorder.Code)
	}
	if got := upstream.Header.Get("X-Auth-Email"); got != "ada@example.com" {
		t.Errorf("X-Auth-Email = %q, want ada@example.com", got)
	}

	// And a token the provider rejects must not pass.
	reached = false
	recorder = httptest.NewRecorder()
	oauth.AuthMiddleware(nextRecorder(&reached, &upstream)).ServeHTTP(recorder,
		browserRequest("/protected", &http.Cookie{Name: GomaAccessToken, Value: "opaque-forged-token"}))
	if reached {
		t.Fatal("token rejected by the provider reached the upstream")
	}
}

// Nothing to verify against means the route is not guarded at all, so the
// request fails instead of being waved through.
func TestOauthFailsClosedWithoutVerifier(t *testing.T) {
	oauth := &Oauth{
		Path:        "/",
		Paths:       []string{"/*"},
		Provider:    "custom",
		ClientID:    "goma",
		RedirectURL: "https://example.com/callback",
		Endpoint:    OauthEndpoint{AuthURL: "https://idp.example.com/authorize"},
	}

	reached := false
	var upstream *http.Request
	recorder := httptest.NewRecorder()
	oauth.AuthMiddleware(nextRecorder(&reached, &upstream)).ServeHTTP(recorder,
		browserRequest("/protected", &http.Cookie{Name: GomaAccessToken, Value: "anything"}))

	if reached {
		t.Fatal("unverifiable token reached the upstream")
	}
	if recorder.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", recorder.Code, http.StatusInternalServerError)
	}
}

// An API client cannot render a login page: it needs a 401 it can act on.
func TestOauthChallengeMatchesClientType(t *testing.T) {
	oauth := &Oauth{
		Path:        "/",
		Paths:       []string{"/*"},
		Provider:    "custom",
		ClientID:    "goma",
		RedirectURL: "https://example.com/callback",
		Endpoint:    OauthEndpoint{AuthURL: "https://idp.example.com/authorize", JwksURL: "https://idp.example.com/jwks"},
	}

	tests := []struct {
		name    string
		headers map[string]string
		method  string
		want    int
	}{
		{"browser navigation", map[string]string{"Accept": "text/html", "Sec-Fetch-Dest": "document"}, http.MethodGet, http.StatusFound},
		{"browser without fetch metadata", map[string]string{"Accept": "text/html"}, http.MethodGet, http.StatusFound},
		{"fetch from a page", map[string]string{"Accept": "*/*", "Sec-Fetch-Dest": "empty"}, http.MethodGet, http.StatusUnauthorized},
		{"xhr", map[string]string{"X-Requested-With": "XMLHttpRequest"}, http.MethodGet, http.StatusUnauthorized},
		{"json api", map[string]string{"Accept": "application/json"}, http.MethodGet, http.StatusUnauthorized},
		{"form post", map[string]string{"Accept": "text/html"}, http.MethodPost, http.StatusUnauthorized},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(test.method, "/protected", nil)
			for name, value := range test.headers {
				request.Header.Set(name, value)
			}
			recorder := httptest.NewRecorder()
			reached := false
			var upstream *http.Request
			oauth.AuthMiddleware(nextRecorder(&reached, &upstream)).ServeHTTP(recorder, request)

			if reached {
				t.Fatal("request without a session reached the upstream")
			}
			if recorder.Code != test.want {
				t.Errorf("status = %d, want %d", recorder.Code, test.want)
			}
		})
	}
}

// The callback must stay reachable, otherwise login cannot complete.
func TestOauthSkipsCallbackPath(t *testing.T) {
	oauth := &Oauth{
		Path:        "/",
		Paths:       []string{"/*"},
		Provider:    "custom",
		ClientID:    "goma",
		RedirectURL: "https://example.com/callback/protected",
		Endpoint:    OauthEndpoint{AuthURL: "https://idp.example.com/authorize", JwksURL: "https://idp.example.com/jwks"},
	}

	reached := false
	var upstream *http.Request
	recorder := httptest.NewRecorder()
	oauth.AuthMiddleware(nextRecorder(&reached, &upstream)).ServeHTTP(recorder,
		browserRequest("/callback/protected?code=abc&state=xyz"))

	if !reached {
		t.Fatalf("callback path was blocked, status = %d", recorder.Code)
	}
}

// Even on the paths it does not guard, the middleware must not let a client
// supply the identity headers the upstream trusts.
func TestOauthStripsIdentityHeadersOnUnguardedPaths(t *testing.T) {
	oauth := &Oauth{
		Path:        "/",
		Paths:       []string{"/admin/*"},
		Provider:    "custom",
		ClientID:    "goma",
		RedirectURL: "https://example.com/callback",
		Endpoint:    OauthEndpoint{AuthURL: "https://idp.example.com/authorize", UserInfoURL: "https://idp.example.com/userinfo"},
		Forward:     &ClaimMapper{Headers: map[string]string{"X-Auth-Email": "email"}},
	}

	// A path the middleware does not guard, so the request is proxied as is.
	request := browserRequest("/public")
	request.Header.Set("X-Auth-Email", "attacker@example.com")

	recorder := httptest.NewRecorder()
	reached := false
	var upstream *http.Request
	oauth.AuthMiddleware(nextRecorder(&reached, &upstream)).ServeHTTP(recorder, request)

	if !reached {
		t.Fatalf("unguarded path was blocked, status = %d", recorder.Code)
	}
	if got := upstream.Header.Get("X-Auth-Email"); got != "" {
		t.Errorf("X-Auth-Email = %q, want the client value stripped", got)
	}

	// And on the guarded path, where the request never reaches the upstream.
	request = browserRequest("/admin/settings")
	request.Header.Set("X-Auth-Email", "attacker@example.com")
	recorder = httptest.NewRecorder()
	oauth.AuthMiddleware(nextRecorder(&reached, &upstream)).ServeHTTP(recorder, request)
	if got := request.Header.Get("X-Auth-Email"); got != "" {
		t.Errorf("X-Auth-Email = %q, want the client value stripped", got)
	}
}

// The JWT middleware owns the same keys and must strip them the same way.
func TestJwtStripsIdentityHeadersOnUnguardedPaths(t *testing.T) {
	jwtAuth := &JwtAuth{
		Path:    "/",
		Paths:   []string{"/admin/*"},
		Secret:  "test-secret",
		Forward: &ClaimMapper{Headers: map[string]string{"X-Auth-Email": "email"}},
	}

	request := httptest.NewRequest(http.MethodGet, "/public", nil)
	request.Header.Set("X-Auth-Email", "attacker@example.com")

	reached := false
	var upstream *http.Request
	recorder := httptest.NewRecorder()
	jwtAuth.AuthMiddleware(nextRecorder(&reached, &upstream)).ServeHTTP(recorder, request)

	if !reached {
		t.Fatalf("unguarded path was blocked, status = %d", recorder.Code)
	}
	if got := upstream.Header.Get("X-Auth-Email"); got != "" {
		t.Errorf("X-Auth-Email = %q, want the client value stripped", got)
	}
}

func TestIsJWT(t *testing.T) {
	key := testRSAKey(t)
	signed := signToken(t, key, "kid", jwt.MapClaims{"sub": "user-1"})

	if !isJWT(signed) {
		t.Error("isJWT(signed token) = false, want true")
	}
	for _, opaque := range []string{"", "ya29.a0AfH6SMB", "a.b", strings.Repeat("x", 40), "not.a.jwt"} {
		if isJWT(opaque) {
			t.Errorf("isJWT(%q) = true, want false", opaque)
		}
	}
}

func TestNewAuthCookie(t *testing.T) {
	secure := httptest.NewRequest(http.MethodGet, "https://example.com/protected", nil)
	cookie := NewAuthCookie(secure, GomaAccessToken, "token", "/app")

	if !cookie.HttpOnly {
		t.Error("cookie is not HttpOnly")
	}
	if !cookie.Secure {
		t.Error("cookie served over TLS is not Secure")
	}
	if cookie.SameSite != http.SameSiteLaxMode {
		t.Errorf("SameSite = %v, want Lax", cookie.SameSite)
	}
	if cookie.Path != "/app" {
		t.Errorf("Path = %q, want /app", cookie.Path)
	}

	plain := httptest.NewRequest(http.MethodGet, "http://example.com/protected", nil)
	if NewAuthCookie(plain, GomaAccessToken, "token", "").Secure {
		t.Error("cookie served over plain HTTP is marked Secure, browsers would drop it")
	}
	if got := NewAuthCookie(plain, GomaAccessToken, "token", "").Path; got != "/" {
		t.Errorf("Path = %q, want / by default", got)
	}
}
