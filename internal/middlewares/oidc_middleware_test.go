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

const (
	testKeyID       = "test-key"
	testClientID    = "goma"
	testSecret      = "test-client-secret"
	testIssuer      = "https://idp.example.com"
	testAuthURL     = "https://idp.example.com/authorize"
	testTokenURL    = "https://idp.example.com/token"
	testRedirectURL = "https://example.com/callback"
	testSubject     = "user-1"
	testEmail       = "ada@example.com"
	testGroup       = "admins"
	testAttacker    = "attacker"
	testGuardedPath = "/admin/.*"

	claimSub     = "sub"
	claimExp     = "exp"
	claimAud     = "aud"
	claimName    = "name"
	claimEmail   = "email"
	claimGroups  = "groups"
	testTenant   = "acme"
	headerUser   = "X-Auth-User"
	headerEmail  = "X-Auth-Email"
	headerGroup  = "X-Auth-Groups"
	headerName   = "X-Auth-Name"
	headerAccept = "Accept"

	claimEmailVerified = "email_verified"
	keyTypeRSA         = "RSA"
	testIDToken        = "id-token"
	testLogoutPath     = "/logout"
	testFreshSession   = "fresh"
	headerIDToken      = "X-Auth-Id-Token"
)

// jwksServer serves a JWKS for key, so the middleware can verify tokens the
// test signs with it.
func jwksServer(t *testing.T, key *rsa.PrivateKey) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(Jwks{Keys: []Jwk{{
			Kid: testKeyID,
			Kty: keyTypeRSA,
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

// testConfig is a minimal working configuration; tests override what they need.
func testConfig() OIDCConfig {
	return OIDCConfig{
		Path:         "/",
		Paths:        []string{testAllPaths},
		Provider:     ProviderCustom,
		ClientID:     testClientID,
		ClientSecret: testSecret,
		RedirectURL:  testRedirectURL,
		CallbackPath: "/callback",
		Endpoint:     OauthEndpoint{AuthURL: testAuthURL, TokenURL: testTokenURL},
	}
}

func newTestOIDC(t *testing.T, config OIDCConfig) *OIDC {
	t.Helper()
	middleware, err := NewOIDC(config)
	if err != nil {
		t.Fatalf("NewOIDC() = %v, want nil", err)
	}
	return middleware
}

// nextRecorder reports whether the request reached the upstream, and captures it.
func nextRecorder(reached *bool, captured **http.Request) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*reached = true
		*captured = r
		w.WriteHeader(http.StatusOK)
	})
}

func browserRequest(path string) *http.Request {
	request := httptest.NewRequest(http.MethodGet, path, nil)
	request.Header.Set(headerAccept, contentTypeHTML+",application/xhtml+xml")
	return request
}

// signedIn builds a browser request to a guarded path, already carrying the
// session, by asking the middleware's own store to write it.
func signedIn(t *testing.T, o *OIDC, session *Session) *http.Request {
	t.Helper()
	const path = "/protected"

	if session.IssuedAt == 0 {
		session.IssuedAt = time.Now().Unix()
	}
	if session.LastSeen == 0 {
		session.LastSeen = time.Now().Unix()
	}

	seed := httptest.NewRequest(http.MethodGet, path, nil)
	recorder := httptest.NewRecorder()
	if err := o.store.Save(recorder, seed, session); err != nil {
		t.Fatalf("failed to seed the session: %v", err)
	}

	request := browserRequest(path)
	for _, cookie := range recorder.Result().Cookies() {
		request.AddCookie(cookie)
	}
	return request
}

func serveOIDC(o *OIDC, request *http.Request) (*httptest.ResponseRecorder, bool, *http.Request) {
	reached := false
	var upstream *http.Request
	recorder := httptest.NewRecorder()
	o.AuthMiddleware(nextRecorder(&reached, &upstream)).ServeHTTP(recorder, request)
	return recorder, reached, upstream
}

// A token nobody signed must not be accepted just because its "exp" is in the
// future.
func TestOIDCRejectsForgedToken(t *testing.T) {
	key := testRSAKey(t)
	jwks := jwksServer(t, key)

	attacker := testRSAKey(t)
	forged := signToken(t, attacker, testKeyID, jwt.MapClaims{
		claimSub: testAttacker,
		claimExp: time.Now().Add(time.Hour).Unix(),
	})

	config := testConfig()
	config.Endpoint.JwksURL = jwks.URL
	oidc := newTestOIDC(t, config)

	recorder, reached, _ := serveOIDC(oidc, signedIn(t, oidc, &Session{AccessToken: forged}))

	if reached {
		t.Fatal("forged token reached the upstream")
	}
	if recorder.Code != http.StatusFound {
		t.Errorf("status = %d, want %d (redirect to the provider)", recorder.Code, http.StatusFound)
	}
}

// An unsigned or alg=none token must not be accepted either.
func TestOIDCRejectsUnsignedToken(t *testing.T) {
	key := testRSAKey(t)
	jwks := jwksServer(t, key)

	unsigned, err := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{
		claimSub: testAttacker,
		claimExp: time.Now().Add(time.Hour).Unix(),
	}).SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("failed to build unsigned token: %v", err)
	}

	config := testConfig()
	config.Endpoint.JwksURL = jwks.URL
	oidc := newTestOIDC(t, config)

	_, reached, _ := serveOIDC(oidc, signedIn(t, oidc, &Session{AccessToken: unsigned}))
	if reached {
		t.Fatal("unsigned token reached the upstream")
	}
}

func TestOIDCAcceptsVerifiedTokenAndForwardsClaims(t *testing.T) {
	key := testRSAKey(t)
	jwks := jwksServer(t, key)

	accessToken := signToken(t, key, testKeyID, jwt.MapClaims{
		claimSub:    testSubject,
		claimEmail:  testEmail,
		claimGroups: []string{testGroup},
		"iss":       testIssuer,
		claimAud:    testClientID,
		claimExp:    time.Now().Add(time.Hour).Unix(),
	})

	config := testConfig()
	config.Issuer = testIssuer
	config.Audience = testClientID
	config.Endpoint.JwksURL = jwks.URL
	config.ClaimsSource = []string{ClaimSourceAccessToken}
	config.Forward = &ClaimMapper{Headers: map[string]string{
		headerUser:  claimSub,
		headerEmail: claimEmail,
		headerGroup: claimGroups,
	}}
	oidc := newTestOIDC(t, config)

	request := signedIn(t, oidc, &Session{AccessToken: accessToken})
	request.Header.Set(headerEmail, "attacker@example.com")

	recorder, reached, upstream := serveOIDC(oidc, request)
	if !reached {
		t.Fatalf("verified token did not reach the upstream, status = %d", recorder.Code)
	}
	if got := upstream.Header.Get(headerUser); got != testSubject {
		t.Errorf("%s = %q, want %s", headerUser, got, testSubject)
	}
	if got := upstream.Header.Get(headerEmail); got != testEmail {
		t.Errorf("%s = %q, want the verified claim, not the client's", headerEmail, got)
	}
	if got := upstream.Header.Get(headerGroup); got != testGroup {
		t.Errorf("%s = %q, want %s", headerGroup, got, testGroup)
	}
}

// A token minted for a different client of the same provider must not pass.
func TestOIDCEnforcesIssuerAndAudience(t *testing.T) {
	key := testRSAKey(t)
	jwks := jwksServer(t, key)

	otherClient := signToken(t, key, testKeyID, jwt.MapClaims{
		claimSub: testSubject,
		"iss":    testIssuer,
		claimAud: "another-app",
		claimExp: time.Now().Add(time.Hour).Unix(),
	})

	config := testConfig()
	config.Issuer = testIssuer
	config.Audience = testClientID
	config.Endpoint.JwksURL = jwks.URL
	oidc := newTestOIDC(t, config)

	_, reached, _ := serveOIDC(oidc, signedIn(t, oidc, &Session{AccessToken: otherClient}))
	if reached {
		t.Fatal("token issued to another client reached the upstream")
	}
}

// The ID token's audience is this client by definition, whatever the config says.
func TestOIDCEnforcesIDTokenAudience(t *testing.T) {
	key := testRSAKey(t)
	jwks := jwksServer(t, key)

	idToken := signToken(t, key, testKeyID, jwt.MapClaims{
		claimSub: testSubject,
		claimAud: "another-app",
		claimExp: time.Now().Add(time.Hour).Unix(),
	})
	accessToken := signToken(t, key, testKeyID, jwt.MapClaims{
		claimSub: testSubject,
		claimExp: time.Now().Add(time.Hour).Unix(),
	})

	config := testConfig()
	config.Endpoint.JwksURL = jwks.URL
	oidc := newTestOIDC(t, config)

	_, reached, _ := serveOIDC(oidc, signedIn(t, oidc, &Session{AccessToken: accessToken, IDToken: idToken}))
	if reached {
		t.Fatal("ID token issued to another client reached the upstream")
	}
}

// Opaque access tokens (Google, GitHub, Facebook) are validated by asking the
// provider's user info endpoint, which also supplies the claims to forward.
func TestOIDCVerifiesOpaqueTokenWithUserInfo(t *testing.T) {
	userInfo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer opaque-valid-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"sub":%q,"email":%q}`, testSubject, testEmail)
	}))
	defer userInfo.Close()

	config := testConfig()
	config.Endpoint.UserInfoURL = userInfo.URL
	config.Forward = &ClaimMapper{Headers: map[string]string{headerEmail: claimEmail}}
	oidc := newTestOIDC(t, config)

	recorder, reached, upstream := serveOIDC(oidc,
		signedIn(t, oidc, &Session{AccessToken: "opaque-valid-token"}))
	if !reached {
		t.Fatalf("valid opaque token did not reach the upstream, status = %d", recorder.Code)
	}
	if got := upstream.Header.Get(headerEmail); got != testEmail {
		t.Errorf("%s = %q, want %s", headerEmail, got, testEmail)
	}

	// And a token the provider rejects must not pass.
	_, reached, _ = serveOIDC(oidc,
		signedIn(t, oidc, &Session{AccessToken: "opaque-forged-token"}))
	if reached {
		t.Fatal("token rejected by the provider reached the upstream")
	}
}

// Nothing to verify against means the route is not guarded at all, so the
// request fails instead of being waved through.
func TestOIDCFailsClosedWithoutVerifier(t *testing.T) {
	oidc := newTestOIDC(t, testConfig())

	recorder, reached, _ := serveOIDC(oidc,
		signedIn(t, oidc, &Session{AccessToken: "anything"}))
	if reached {
		t.Fatal("unverifiable token reached the upstream")
	}
	if recorder.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", recorder.Code, http.StatusInternalServerError)
	}
}

// An API client cannot render a login page: it needs a 401 it can act on.
func TestOIDCChallengeMatchesClientType(t *testing.T) {
	config := testConfig()
	config.Endpoint.JwksURL = "https://idp.example.com/jwks"
	oidc := newTestOIDC(t, config)

	tests := []struct {
		name    string
		headers map[string]string
		method  string
		want    int
	}{
		{"browser navigation", map[string]string{headerAccept: contentTypeHTML, "Sec-Fetch-Dest": "document"}, http.MethodGet, http.StatusFound},
		{"browser without fetch metadata", map[string]string{headerAccept: contentTypeHTML}, http.MethodGet, http.StatusFound},
		{"fetch from a page", map[string]string{headerAccept: "*/*", "Sec-Fetch-Dest": "empty"}, http.MethodGet, http.StatusUnauthorized},
		{"xhr", map[string]string{"X-Requested-With": "XMLHttpRequest"}, http.MethodGet, http.StatusUnauthorized},
		{"json api", map[string]string{headerAccept: "application/json"}, http.MethodGet, http.StatusUnauthorized},
		{"form post", map[string]string{headerAccept: contentTypeHTML}, http.MethodPost, http.StatusUnauthorized},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(test.method, "/protected", nil)
			for name, value := range test.headers {
				request.Header.Set(name, value)
			}
			recorder, reached, _ := serveOIDC(oidc, request)

			if reached {
				t.Fatal("request without a session reached the upstream")
			}
			if recorder.Code != test.want {
				t.Errorf("status = %d, want %d", recorder.Code, test.want)
			}
		})
	}
}

// The callback and logout endpoints must stay reachable, otherwise login and
// logout cannot complete.
func TestOIDCSkipsItsOwnEndpoints(t *testing.T) {
	config := testConfig()
	config.CallbackPath = "/callback/protected"
	config.LogoutPath = testLogoutPath
	config.Endpoint.JwksURL = "https://idp.example.com/jwks"
	oidc := newTestOIDC(t, config)

	for _, path := range []string{"/callback/protected?code=abc&state=xyz", testLogoutPath} {
		recorder, reached, _ := serveOIDC(oidc, browserRequest(path))
		if !reached {
			t.Errorf("%s was blocked by the middleware, status = %d", path, recorder.Code)
		}
	}
}

// Even on the paths it does not guard, the middleware must not let a client
// supply the identity headers the upstream trusts.
func TestOIDCStripsIdentityHeadersOnUnguardedPaths(t *testing.T) {
	config := testConfig()
	config.Paths = []string{testGuardedPath}
	config.Endpoint.UserInfoURL = "https://idp.example.com/userinfo"
	config.Forward = &ClaimMapper{Headers: map[string]string{headerEmail: claimEmail}}
	oidc := newTestOIDC(t, config)

	// A path the middleware does not guard, so the request is proxied as is.
	request := browserRequest("/public")
	request.Header.Set(headerEmail, "attacker@example.com")

	recorder, reached, upstream := serveOIDC(oidc, request)
	if !reached {
		t.Fatalf("unguarded path was blocked, status = %d", recorder.Code)
	}
	if got := upstream.Header.Get(headerEmail); got != "" {
		t.Errorf("%s = %q, want the client value stripped", headerEmail, got)
	}

	// And on the guarded path, where the request never reaches the upstream.
	request = browserRequest("/admin/settings")
	request.Header.Set(headerEmail, "attacker@example.com")
	_, _, _ = serveOIDC(oidc, request)
	if got := request.Header.Get(headerEmail); got != "" {
		t.Errorf("%s = %q, want the client value stripped", headerEmail, got)
	}
}

// The JWT middleware owns the same keys and must strip them the same way.
func TestJwtStripsIdentityHeadersOnUnguardedPaths(t *testing.T) {
	jwtAuth := &JwtAuth{
		Path:    "/",
		Paths:   []string{testGuardedPath},
		Secret:  "test-secret",
		Forward: &ClaimMapper{Headers: map[string]string{headerEmail: claimEmail}},
	}

	request := httptest.NewRequest(http.MethodGet, "/public", nil)
	request.Header.Set(headerEmail, "attacker@example.com")

	reached := false
	var upstream *http.Request
	recorder := httptest.NewRecorder()
	jwtAuth.AuthMiddleware(nextRecorder(&reached, &upstream)).ServeHTTP(recorder, request)

	if !reached {
		t.Fatalf("unguarded path was blocked, status = %d", recorder.Code)
	}
	if got := upstream.Header.Get(headerEmail); got != "" {
		t.Errorf("%s = %q, want the client value stripped", headerEmail, got)
	}
}

// claimsExpression authorizes the user, not just authenticates them.
func TestOIDCClaimsExpressionAuthorizes(t *testing.T) {
	key := testRSAKey(t)
	jwks := jwksServer(t, key)

	token := func(groups []string) string {
		return signToken(t, key, testKeyID, jwt.MapClaims{
			claimSub:    testSubject,
			claimGroups: groups,
			claimExp:    time.Now().Add(time.Hour).Unix(),
		})
	}

	config := testConfig()
	config.Endpoint.JwksURL = jwks.URL
	config.ClaimsSource = []string{ClaimSourceAccessToken}
	config.ClaimsExpression = "Contains('groups', 'admins')"
	oidc := newTestOIDC(t, config)

	_, reached, _ := serveOIDC(oidc, signedIn(t, oidc, &Session{AccessToken: token([]string{testGroup})}))
	if !reached {
		t.Error("a user matching the expression was denied")
	}

	recorder, reached, _ := serveOIDC(oidc, signedIn(t, oidc, &Session{AccessToken: token([]string{"interns"})}))
	if reached {
		t.Fatal("a user not matching the expression reached the upstream")
	}
	if recorder.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", recorder.Code, http.StatusForbidden)
	}
}

// An unparsable expression must stop the middleware from loading, rather than
// silently letting everyone through.
func TestOIDCRejectsInvalidClaimsExpression(t *testing.T) {
	config := testConfig()
	config.ClaimsExpression = "Contains('groups'"
	if _, err := NewOIDC(config); err == nil {
		t.Error("NewOIDC() = nil error, want a parse failure")
	}
}

func TestIsJWT(t *testing.T) {
	key := testRSAKey(t)
	signed := signToken(t, key, "kid", jwt.MapClaims{claimSub: testSubject})

	if !isJWT(signed) {
		t.Error("isJWT(signed token) = false, want true")
	}
	for _, opaque := range []string{"", "ya29.a0AfH6SMB", "a.b", strings.Repeat("x", 40), "not.a.jwt"} {
		if isJWT(opaque) {
			t.Errorf("isJWT(%q) = true, want false", opaque)
		}
	}
}
