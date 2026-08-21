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
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// fakeProvider is an identity provider that issues tokens the test can predict:
// a token endpoint, a JWKS, and a user info endpoint.
type fakeProvider struct {
	server *httptest.Server
	key    *rsa.PrivateKey
	// lastForm records what the gateway sent to the token endpoint.
	lastForm url.Values
	// nonce goes into the ID token the token endpoint returns.
	nonce string
	// refreshCount counts refresh_token grants.
	refreshCount int
}

func newFakeProvider(t *testing.T) *fakeProvider {
	t.Helper()
	provider := &fakeProvider{key: testRSAKey(t)}

	mux := http.NewServeMux()
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(Jwks{Keys: []Jwk{jwkFor(provider.key)}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		provider.lastForm = r.PostForm
		if r.PostForm.Get("grant_type") == "refresh_token" {
			provider.refreshCount++
		}

		idToken := signToken(t, provider.key, testKeyID, jwt.MapClaims{
			claimSub:   testSubject,
			claimEmail: testEmail,
			claimAud:   testClientID,
			"nonce":    provider.nonce,
			claimExp:   time.Now().Add(time.Hour).Unix(),
		})
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token":  "opaque-access-token",
			"refresh_token": "opaque-refresh-token",
			"id_token":      idToken,
			"token_type":    "Bearer",
			"expires_in":    3600,
		})
	})
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			claimSub: testSubject, claimGroups: []string{testGroup},
		})
	})

	provider.server = httptest.NewServer(mux)
	t.Cleanup(provider.server.Close)
	return provider
}

func jwkFor(key *rsa.PrivateKey) Jwk {
	exponent := []byte{byte(key.E >> 16), byte(key.E >> 8), byte(key.E)}
	for len(exponent) > 1 && exponent[0] == 0 {
		exponent = exponent[1:]
	}
	return Jwk{
		Kid: testKeyID,
		Kty: keyTypeRSA,
		N:   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(exponent),
	}
}

func (p *fakeProvider) config() OIDCConfig {
	config := testConfig()
	config.Endpoint = OauthEndpoint{
		AuthURL:     p.server.URL + "/authorize",
		TokenURL:    p.server.URL + "/token",
		UserInfoURL: p.server.URL + "/userinfo",
		JwksURL:     p.server.URL + "/jwks",
	}
	return config
}

// login walks a browser through the whole flow and returns the cookies it ends
// up holding, plus the callback's response.
func login(t *testing.T, o *OIDC, provider *fakeProvider, startPath string) ([]*http.Cookie, *httptest.ResponseRecorder) {
	t.Helper()

	// The guarded request is redirected to the provider.
	start, _, _ := serveOIDC(o, browserRequest(startPath))
	if start.Code != http.StatusFound {
		t.Fatalf("login did not start, status = %d", start.Code)
	}
	authURL, err := url.Parse(start.Header().Get("Location"))
	if err != nil {
		t.Fatalf("unparsable authorization URL: %v", err)
	}
	provider.nonce = authURL.Query().Get("nonce")

	// The provider sends the browser back with a code, and the browser still
	// holds the flow cookie.
	callback := httptest.NewRequest(http.MethodGet,
		o.CallbackPath+"?code=auth-code&state="+url.QueryEscape(authURL.Query().Get("state")), nil)
	for _, cookie := range start.Result().Cookies() {
		callback.AddCookie(cookie)
	}

	recorder := httptest.NewRecorder()
	o.CallbackHandler(recorder, callback)
	return recorder.Result().Cookies(), recorder
}

func TestOIDCLoginFlow(t *testing.T) {
	provider := newFakeProvider(t)
	oidc := newTestOIDC(t, provider.config())

	cookies, callback := login(t, oidc, provider, "/protected/page?tab=2")

	if callback.Code != http.StatusSeeOther {
		t.Fatalf("callback status = %d, want %d", callback.Code, http.StatusSeeOther)
	}
	// The user returns to what they originally asked for, not a fixed page.
	if got := callback.Header().Get("Location"); got != "/protected/page?tab=2" {
		t.Errorf("Location = %q, want the originally requested URL", got)
	}

	// PKCE: the gateway sent a challenge, then the matching verifier.
	if got := provider.lastForm.Get("code_verifier"); got == "" {
		t.Error("the token exchange carried no code_verifier")
	}

	// And the session that came out of it is accepted on the next request.
	request := browserRequest("/protected/page")
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	recorder, reached, _ := serveOIDC(oidc, request)
	if !reached {
		t.Fatalf("the session opened by the callback was not accepted, status = %d", recorder.Code)
	}
}

// The authorization request must carry a fresh state, a nonce, and an S256
// challenge derived from a verifier the gateway keeps to itself.
func TestOIDCAuthorizationRequestParameters(t *testing.T) {
	provider := newFakeProvider(t)
	oidc := newTestOIDC(t, provider.config())

	first, _, _ := serveOIDC(oidc, browserRequest("/protected"))
	second, _, _ := serveOIDC(oidc, browserRequest("/protected"))

	firstURL, _ := url.Parse(first.Header().Get("Location"))
	secondURL, _ := url.Parse(second.Header().Get("Location"))

	state := firstURL.Query().Get("state")
	if state == "" {
		t.Fatal("the authorization request carried no state")
	}
	if state == secondURL.Query().Get("state") {
		t.Error("two logins shared a state, it must be random per request")
	}
	if firstURL.Query().Get("nonce") == "" {
		t.Error("the authorization request carried no nonce")
	}
	if got := firstURL.Query().Get("code_challenge_method"); got != "S256" {
		t.Errorf("code_challenge_method = %q, want S256", got)
	}

	challenge := firstURL.Query().Get("code_challenge")
	if challenge == "" {
		t.Fatal("the authorization request carried no code_challenge")
	}
	// The verifier stays in the sealed flow cookie; only its hash is sent.
	flow := readFlowFrom(t, oidc, first)
	sum := sha256.Sum256([]byte(flow.Verifier))
	if want := base64.RawURLEncoding.EncodeToString(sum[:]); challenge != want {
		t.Error("code_challenge is not the S256 hash of the stored verifier")
	}
	if strings.Contains(first.Header().Get("Location"), flow.Verifier) {
		t.Error("the code verifier was sent to the provider")
	}
}

func readFlowFrom(t *testing.T, o *OIDC, recorder *httptest.ResponseRecorder) *flowState {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	for _, cookie := range recorder.Result().Cookies() {
		request.AddCookie(cookie)
	}
	flow, err := o.readFlowCookie(request)
	if err != nil {
		t.Fatalf("failed to read the flow cookie: %v", err)
	}
	return flow
}

// A callback that does not belong to a login this browser started must be
// refused: that is what stops an attacker's code being redeemed in a victim's
// session.
func TestOIDCCallbackRejectsForeignRequests(t *testing.T) {
	provider := newFakeProvider(t)
	oidc := newTestOIDC(t, provider.config())

	start, _, _ := serveOIDC(oidc, browserRequest("/protected"))
	authURL, _ := url.Parse(start.Header().Get("Location"))
	provider.nonce = authURL.Query().Get("nonce")
	validState := authURL.Query().Get("state")

	tests := []struct {
		name       string
		query      string
		withCookie bool
		want       int
	}{
		{"no flow cookie", "?code=c&state=" + validState, false, http.StatusBadRequest},
		{"mismatched state", "?code=c&state=attacker-state", true, http.StatusBadRequest},
		{"missing state", "?code=c", true, http.StatusBadRequest},
		{"missing code", "?state=" + validState, true, http.StatusBadRequest},
		{"provider error", "?error=access_denied&state=" + validState, true, http.StatusForbidden},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, oidc.CallbackPath+test.query, nil)
			if test.withCookie {
				for _, cookie := range start.Result().Cookies() {
					request.AddCookie(cookie)
				}
			}
			recorder := httptest.NewRecorder()
			oidc.CallbackHandler(recorder, request)

			if recorder.Code != test.want {
				t.Errorf("status = %d, want %d", recorder.Code, test.want)
			}
			if len(sessionCookies(recorder)) > 0 {
				t.Error("a session was opened for a rejected callback")
			}
		})
	}
}

// An ID token minted for another login must not be replayable into this one.
func TestOIDCCallbackEnforcesNonce(t *testing.T) {
	provider := newFakeProvider(t)
	oidc := newTestOIDC(t, provider.config())

	start, _, _ := serveOIDC(oidc, browserRequest("/protected"))
	authURL, _ := url.Parse(start.Header().Get("Location"))
	// The provider returns an ID token bound to a different login.
	provider.nonce = "nonce-from-another-login"

	callback := httptest.NewRequest(http.MethodGet,
		oidc.CallbackPath+"?code=c&state="+url.QueryEscape(authURL.Query().Get("state")), nil)
	for _, cookie := range start.Result().Cookies() {
		callback.AddCookie(cookie)
	}
	recorder := httptest.NewRecorder()
	oidc.CallbackHandler(recorder, callback)

	if recorder.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", recorder.Code, http.StatusForbidden)
	}
	if len(sessionCookies(recorder)) > 0 {
		t.Error("a session was opened despite the nonce mismatch")
	}
}

func sessionCookies(recorder *httptest.ResponseRecorder) []*http.Cookie {
	var found []*http.Cookie
	for _, cookie := range recorder.Result().Cookies() {
		if cookie.Name == DefaultSessionCookieName && cookie.Value != "" {
			found = append(found, cookie)
		}
	}
	return found
}

// A login endpoint that returns to a URL of the caller's choosing is an open
// redirect; only paths on this gateway are accepted.
func TestSafeReturnTo(t *testing.T) {
	for _, accepted := range []string{"/", "/protected", "/protected/page?tab=2", "/a/b#c"} {
		if safeReturnTo(accepted) != accepted {
			t.Errorf("safeReturnTo(%q) rejected a path on this gateway", accepted)
		}
	}
	for _, rejected := range []string{
		"", "//evil.example.com", "/\\evil.example.com", "https://evil.example.com",
		"http://evil.example.com/path", "evil.example.com",
	} {
		if got := safeReturnTo(rejected); got != "" {
			t.Errorf("safeReturnTo(%q) = %q, want it rejected", rejected, got)
		}
	}
}

func TestOIDCCallbackIgnoresForeignReturnTo(t *testing.T) {
	provider := newFakeProvider(t)
	oidc := newTestOIDC(t, provider.config())

	// A flow whose stored destination points off-site, as a tampered or
	// hand-crafted cookie might.
	flow := &flowState{State: "state-value", Nonce: "nonce-value",
		ReturnTo: "//evil.example.com/", IssuedAt: time.Now().Unix()}
	if got := oidc.postLoginDestination(flow); strings.Contains(got, "evil.example.com") {
		t.Errorf("postLoginDestination = %q, want the off-site destination discarded", got)
	}
}

func TestOIDCLogout(t *testing.T) {
	provider := newFakeProvider(t)
	config := provider.config()
	config.LogoutPath = testLogoutPath
	config.PostLogoutRedirect = "/goodbye"
	oidc := newTestOIDC(t, config)

	cookies, _ := login(t, oidc, provider, "/protected")

	request := httptest.NewRequest(http.MethodGet, testLogoutPath, nil)
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	recorder := httptest.NewRecorder()
	oidc.LogoutHandler(recorder, request)

	if recorder.Code != http.StatusSeeOther {
		t.Errorf("status = %d, want %d", recorder.Code, http.StatusSeeOther)
	}
	if got := recorder.Header().Get("Location"); got != "/goodbye" {
		t.Errorf("Location = %q, want /goodbye", got)
	}

	// The session cookie is expired, and what is left no longer authenticates.
	cleared := false
	for _, cookie := range recorder.Result().Cookies() {
		if cookie.Name == DefaultSessionCookieName && cookie.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Error("logout did not clear the session cookie")
	}

	next := browserRequest("/protected")
	for _, cookie := range recorder.Result().Cookies() {
		next.AddCookie(cookie)
	}
	if _, reached, _ := serveOIDC(oidc, next); reached {
		t.Error("a logged-out session still reached the upstream")
	}
}

// When the provider supports RP-initiated logout, ending the gateway session
// must also end the provider's.
func TestOIDCLogoutRedirectsToProvider(t *testing.T) {
	endSession := "https://idp.example.com/end-session"
	metadata := ProviderMetadata{
		Issuer:                "https://issuer.example.com",
		AuthorizationEndpoint: "https://idp.example.com/authorize",
		TokenEndpoint:         "https://idp.example.com/token",
		EndSessionEndpoint:    endSession,
	}
	discoveryServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(metadata)
	}))
	defer discoveryServer.Close()
	metadata.Issuer = discoveryServer.URL
	resetDiscoveryCache()

	config := testConfig()
	config.Issuer = discoveryServer.URL
	config.Endpoint = OauthEndpoint{}
	config.LogoutPath = testLogoutPath
	oidc := newTestOIDC(t, config)

	request := httptest.NewRequest(http.MethodGet, testLogoutPath, nil)
	recorder := httptest.NewRecorder()
	if err := oidc.store.Save(recorder, request,
		&Session{IDToken: testIDToken, IssuedAt: time.Now().Unix(), LastSeen: time.Now().Unix()}); err != nil {
		t.Fatalf("failed to seed the session: %v", err)
	}
	for _, cookie := range recorder.Result().Cookies() {
		request.AddCookie(cookie)
	}

	recorder = httptest.NewRecorder()
	oidc.LogoutHandler(recorder, request)

	location, err := url.Parse(recorder.Header().Get("Location"))
	if err != nil {
		t.Fatalf("unparsable Location: %v", err)
	}
	if !strings.HasPrefix(location.String(), endSession) {
		t.Fatalf("Location = %q, want the provider's end session endpoint", location)
	}
	if got := location.Query().Get("id_token_hint"); got != testIDToken {
		t.Errorf("id_token_hint = %q, want the session's ID token", got)
	}
}

func resetDiscoveryCache() {
	discoveryStore.mu.Lock()
	discoveryStore.entries = make(map[string]*discoveryEntry)
	discoveryStore.mu.Unlock()
}

// A provider that rotates refresh tokens invalidates the old one on use, so
// concurrent requests must share a single exchange rather than racing.
func TestOIDCRefreshIsCoalesced(t *testing.T) {
	provider := newFakeProvider(t)
	oidc := newTestOIDC(t, provider.config())
	resetRefreshGroup()

	// An access token that is a JWT but has expired, so every request has to
	// refresh before it can be served.
	expired := signToken(t, provider.key, testKeyID, jwt.MapClaims{
		claimSub: testSubject,
		claimExp: time.Now().Add(-time.Hour).Unix(),
	})
	session := &Session{
		AccessToken:  expired,
		RefreshToken: "rotating-refresh-token",
		IssuedAt:     time.Now().Unix(),
		LastSeen:     time.Now().Unix(),
	}

	seed := httptest.NewRequest(http.MethodGet, "/protected", nil)
	recorder := httptest.NewRecorder()
	if err := oidc.store.Save(recorder, seed, session); err != nil {
		t.Fatalf("failed to seed the session: %v", err)
	}
	cookies := recorder.Result().Cookies()

	var group sync.WaitGroup
	results := make([]bool, 8)
	for index := range results {
		group.Add(1)
		go func(index int) {
			defer group.Done()
			request := browserRequest("/protected")
			for _, cookie := range cookies {
				request.AddCookie(cookie)
			}
			_, results[index], _ = serveOIDC(oidc, request)
		}(index)
	}
	group.Wait()

	for index, reached := range results {
		if !reached {
			t.Errorf("request %d was not served after the refresh", index)
		}
	}
	if provider.refreshCount != 1 {
		t.Errorf("the refresh token was exchanged %d times, want 1", provider.refreshCount)
	}
}

func resetRefreshGroup() {
	refreshGroup.mu.Lock()
	refreshGroup.calls = make(map[string]*refreshCall)
	refreshGroup.mu.Unlock()
}
