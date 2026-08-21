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
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
)

// Claim sources, in the order they may be listed in claimsSource.
const (
	ClaimSourceIDToken     = "id_token"
	ClaimSourceUserInfo    = "userinfo"
	ClaimSourceAccessToken = "access_token"
)

const (
	// userInfoCacheTTL bounds how long a user info response is reused. It is
	// also how long a token revoked at the provider keeps working when the
	// provider issues opaque tokens, so it stays short.
	userInfoCacheTTL = 60 * time.Second
	// userInfoNegativeTTL caches rejections, so a flood of forged tokens cannot
	// be amplified into a flood of requests against the identity provider.
	userInfoNegativeTTL     = 10 * time.Second
	userInfoRequestTimeout  = 10 * time.Second
	maxUserInfoCacheEntries = 2048
	// maxUserInfoBytes bounds the user info response we are willing to decode.
	maxUserInfoBytes = 1 << 20
)

// DefaultClaimsSource lists claim sources in increasing order of precedence:
// the ID token is the identity assertion OIDC defines, so it wins.
var DefaultClaimsSource = []string{ClaimSourceAccessToken, ClaimSourceUserInfo, ClaimSourceIDToken}

// errNoVerifier means the middleware has no way to establish that the session's
// tokens are genuine. Sending the user back to the provider would only produce
// another unverifiable token, so the request fails instead of looping.
var errNoVerifier = errors.New("cannot verify the session: set endpoint.jwksUrl for JWT tokens, or endpoint.userInfoUrl for opaque ones")

// OIDCConfig is everything the middleware needs to run an OpenID Connect login
// flow on behalf of a route.
type OIDCConfig struct {
	// Route path and the paths within it this middleware guards.
	Path    string
	Paths   []string
	Origins []string

	ClientID     string
	ClientSecret string
	// Provider names a well-known provider, or "custom".
	Provider string
	// Issuer enables discovery: endpoints left empty are read from the
	// provider's /.well-known/openid-configuration document.
	Issuer string
	// Audience, when set, is enforced on JWT access tokens.
	Audience string
	Scopes   []string
	// Endpoint overrides anything discovery would supply.
	Endpoint OauthEndpoint

	// RedirectURL is the callback URL registered with the provider, and
	// CallbackPath is its path on this gateway.
	RedirectURL  string
	CallbackPath string
	// LogoutPath, when set, ends the session.
	LogoutPath string
	// PostLoginRedirect is where a user lands after signing in. Empty means the
	// URL they originally asked for.
	PostLoginRedirect  string
	PostLogoutRedirect string

	// DisablePKCE turns off the proof key on the authorization code exchange.
	// The zero value keeps PKCE on: a caller that forgets the field gets the
	// safe behaviour rather than the weak one.
	DisablePKCE bool
	// ClaimsSource lists where user claims are read from, in increasing order
	// of precedence.
	ClaimsSource []string
	// ClaimsExpression is an authorization rule evaluated against the claims.
	ClaimsExpression string
	// Forward projects the user's claims onto the upstream request.
	Forward *ClaimMapper

	Session SessionOptions
}

// OIDC authenticates browser users against an OpenID Connect provider, keeps
// the session at the gateway, and projects the user's identity onto the
// requests it proxies.
type OIDC struct {
	OIDCConfig

	store            SessionStore
	flowSealer       *sealer
	claimsExpression Expression
}

// NewOIDC prepares the middleware: it builds the session store, derives the
// keys that seal session and flow state, and compiles the authorization rule.
func NewOIDC(config OIDCConfig) (*OIDC, error) {
	if config.ClientID == "" || config.ClientSecret == "" {
		return nil, errors.New("clientId and clientSecret are required")
	}

	// Falling back to the client secret keeps sessions valid across replicas
	// and restarts without asking the operator for a second secret; it is
	// already shared by every gateway serving this route.
	if config.Session.Secret == "" {
		config.Session.Secret = config.ClientSecret
	}

	store, err := NewSessionStore(config.Session)
	if err != nil {
		return nil, err
	}
	flowSealer, err := newSealer(config.Session.Secret, "goma-oidc-flow")
	if err != nil {
		return nil, err
	}

	middleware := &OIDC{OIDCConfig: config, store: store, flowSealer: flowSealer}

	if config.ClaimsExpression != "" {
		expression, err := ParseExpression(config.ClaimsExpression)
		if err != nil {
			return nil, fmt.Errorf("failed to parse claimsExpression: %w", err)
		}
		middleware.claimsExpression = expression
	}
	return middleware, nil
}

func (o *OIDC) AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The mapped keys belong to the gateway on every path of this route, not
		// only the guarded ones: a client that could set them on an unguarded
		// path would be handing the upstream an identity of its choosing.
		o.Forward.Strip(r)

		// The callback and logout endpoints are served by their own handlers.
		if r.URL.Path == o.CallbackPath || (o.LogoutPath != "" && r.URL.Path == o.LogoutPath) {
			next.ServeHTTP(w, r)
			return
		}
		if !isPathMatching(r.URL.Path, o.Path, o.Paths) {
			next.ServeHTTP(w, r)
			return
		}

		ctx := r.Context()
		endpoint, _, err := o.endpoints(ctx)
		if err != nil {
			logger.Error("OIDC provider metadata is unavailable, rejecting request",
				"path", r.URL.Path, "issuer", o.Issuer, "error", err)
			RespondWithError(w, r, http.StatusInternalServerError,
				http.StatusText(http.StatusInternalServerError), o.Origins, getContentType(r))
			return
		}

		session, err := o.store.Load(r)
		if err != nil {
			if !errors.Is(err, errNoSession) {
				logger.Debug("Discarding an unreadable session", "path", r.URL.Path, "error", err)
			}
			o.startAuth(w, r, endpoint, "no session")
			return
		}

		claims, err := o.verify(ctx, endpoint, session)
		if err != nil {
			if errors.Is(err, errNoVerifier) {
				logger.Error("OIDC middleware is not configured to verify tokens, rejecting request",
					"path", r.URL.Path, "error", err)
				RespondWithError(w, r, http.StatusInternalServerError,
					http.StatusText(http.StatusInternalServerError), o.Origins, getContentType(r))
				return
			}
			logger.Debug("Access token rejected, attempting refresh", "path", r.URL.Path, "error", err)

			refreshed, refreshErr := o.refresh(ctx, endpoint, session)
			if refreshErr != nil {
				o.endSession(w, r)
				o.startAuth(w, r, endpoint, refreshErr.Error())
				return
			}
			claims, err = o.verify(ctx, endpoint, refreshed)
			if err != nil {
				o.endSession(w, r)
				o.startAuth(w, r, endpoint, err.Error())
				return
			}
			session = refreshed
			o.saveSession(w, r, session)
		} else if session.needsTouch() {
			session.LastSeen = time.Now().Unix()
			o.saveSession(w, r, session)
		}

		if !o.authorized(claims) {
			logger.Warn("User is not authorized for this route",
				"path", r.URL.Path, "client_ip", RealIP(r), "expression", o.ClaimsExpression)
			RespondWithError(w, r, http.StatusForbidden, http.StatusText(http.StatusForbidden),
				o.Origins, getContentType(r))
			return
		}

		o.Forward.Apply(r, claims)
		o.Forward.ForwardTokens(r, session.AccessToken, session.IDToken)

		next.ServeHTTP(w, r)
	})
}

// authorized evaluates the configured claims expression. A rule that cannot be
// evaluated denies access rather than granting it.
func (o *OIDC) authorized(claims map[string]interface{}) bool {
	if o.claimsExpression == nil {
		return true
	}
	allowed, err := o.claimsExpression.Evaluate(claims)
	if err != nil {
		logger.Error("Failed to evaluate claimsExpression", "expression", o.ClaimsExpression, "error", err)
		return false
	}
	return allowed
}

func (o *OIDC) saveSession(w http.ResponseWriter, r *http.Request, session *Session) {
	if err := o.store.Save(w, r, session); err != nil {
		logger.Error("Failed to save the session", "error", err)
	}
}

func (o *OIDC) endSession(w http.ResponseWriter, r *http.Request) {
	o.store.Clear(w, r)
}

// endpoints resolves the provider's endpoints, preferring anything configured
// explicitly and filling the rest from discovery. It also returns the
// provider's end-session endpoint when it advertises one.
func (o *OIDC) endpoints(ctx context.Context) (OauthEndpoint, string, error) {
	endpoint := o.Endpoint
	endSessionEndpoint := ""

	if o.Issuer != "" && !endpoint.sufficient() {
		metadata, err := Discover(ctx, o.Issuer)
		if err != nil {
			// Explicit endpoints may still be enough to serve the request.
			logger.Warn("OpenID Connect discovery failed", "issuer", o.Issuer, "error", err)
		} else {
			setIfEmpty(&endpoint.AuthURL, metadata.AuthorizationEndpoint)
			setIfEmpty(&endpoint.TokenURL, metadata.TokenEndpoint)
			setIfEmpty(&endpoint.UserInfoURL, metadata.UserInfoEndpoint)
			setIfEmpty(&endpoint.JwksURL, metadata.JwksURI)
			endSessionEndpoint = metadata.EndSessionEndpoint
		}
	}

	if endpoint.AuthURL == "" || endpoint.TokenURL == "" {
		return endpoint, "", errors.New("no authorization or token endpoint is configured or discoverable")
	}
	return endpoint, endSessionEndpoint, nil
}

// sufficient reports whether the configured endpoints are enough to run the
// flow and verify a token without consulting the provider's metadata.
func (endpoint OauthEndpoint) sufficient() bool {
	return endpoint.AuthURL != "" && endpoint.TokenURL != "" &&
		(endpoint.JwksURL != "" || endpoint.UserInfoURL != "")
}

func setIfEmpty(field *string, value string) {
	if *field == "" {
		*field = value
	}
}

// verify establishes that the session is genuine and returns the claims to
// project upstream.
func (o *OIDC) verify(ctx context.Context, endpoint OauthEndpoint, session *Session) (map[string]interface{}, error) {
	sources := o.claimsSources()

	var idClaims, accessClaims, userInfoClaims map[string]interface{}
	idTokenVerified := false

	// The ID token is the only token OIDC defines as an identity assertion, and
	// its audience must be this client — otherwise a token minted for another
	// application of the same provider would be accepted here.
	if session.IDToken != "" && endpoint.JwksURL != "" {
		claims, err := verifyJWT(session.IDToken, endpoint.JwksURL, o.Issuer, o.ClientID)
		if err != nil {
			return nil, fmt.Errorf("id token verification failed: %w", err)
		}
		idClaims = claims
		idTokenVerified = true
	}

	switch {
	case endpoint.JwksURL != "" && isJWT(session.AccessToken):
		claims, err := verifyJWT(session.AccessToken, endpoint.JwksURL, o.Issuer, o.Audience)
		if err != nil {
			return nil, fmt.Errorf("access token verification failed: %w", err)
		}
		accessClaims = claims

	case endpoint.UserInfoURL != "":
		// Opaque access tokens carry no verifiable claims; the provider's user
		// info endpoint is what says whether the token is still valid.
		claims, err := fetchUserInfo(ctx, endpoint.UserInfoURL, session.AccessToken)
		if err != nil {
			return nil, fmt.Errorf("user info verification failed: %w", err)
		}
		userInfoClaims = claims

	default:
		// Nothing could be verified: an opaque access token with no user info
		// endpoint, and no ID token to fall back on.
		if !idTokenVerified {
			return nil, errNoVerifier
		}
	}

	// User info was not needed to verify the session, but may still be the only
	// place a claim we forward lives.
	if userInfoClaims == nil && endpoint.UserInfoURL != "" &&
		slices.Contains(sources, ClaimSourceUserInfo) && o.Forward.Enabled() {
		claims, err := fetchUserInfo(ctx, endpoint.UserInfoURL, session.AccessToken)
		if err != nil {
			logger.Warn("Failed to fetch user info, claims not forwarded from it", "error", err)
		} else {
			userInfoClaims = claims
		}
	}

	claims := map[string]interface{}{}
	// Claims captured at sign-in are the base layer: they carry anything the
	// provider only returned once, such as claims from the initial ID token.
	claims = mergeClaims(claims, session.Claims)
	for _, source := range sources {
		switch source {
		case ClaimSourceAccessToken:
			claims = mergeClaims(claims, accessClaims)
		case ClaimSourceUserInfo:
			claims = mergeClaims(claims, userInfoClaims)
		case ClaimSourceIDToken:
			claims = mergeClaims(claims, idClaims)
		}
	}
	return claimsFromMap(claims), nil
}

// refresh exchanges the refresh token for a new session. Concurrent requests
// for the same session share one exchange, so a provider that rotates refresh
// tokens does not invalidate the session under load.
func (o *OIDC) refresh(ctx context.Context, endpoint OauthEndpoint, session *Session) (*Session, error) {
	if session.RefreshToken == "" {
		return nil, errors.New("session expired and no refresh token is available")
	}

	token, err := refreshGroup.do(session.RefreshToken, func() (*oauth2.Token, error) {
		source := o.oauth2Config(endpoint).TokenSource(ctx, &oauth2.Token{
			AccessToken:  session.AccessToken,
			RefreshToken: session.RefreshToken,
			Expiry:       time.Now().Add(-1 * time.Minute), // Force the exchange.
		})
		return source.Token()
	})
	if err != nil {
		return nil, fmt.Errorf("token refresh failed: %w", err)
	}

	refreshed := &Session{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		IDToken:      session.IDToken,
		Claims:       session.Claims,
		IssuedAt:     session.IssuedAt,
		LastSeen:     time.Now().Unix(),
	}
	if refreshed.RefreshToken == "" {
		refreshed.RefreshToken = session.RefreshToken
	}
	if idToken, ok := token.Extra("id_token").(string); ok && idToken != "" {
		refreshed.IDToken = idToken
	}
	return refreshed, nil
}

func (o *OIDC) claimsSources() []string {
	if len(o.ClaimsSource) == 0 {
		return DefaultClaimsSource
	}
	return o.ClaimsSource
}

// oauth2Config builds the exchange configuration for the resolved endpoints.
func (o *OIDC) oauth2Config(endpoint OauthEndpoint) *oauth2.Config {
	config := &oauth2.Config{
		ClientID:     o.ClientID,
		ClientSecret: o.ClientSecret,
		RedirectURL:  o.RedirectURL,
		Scopes:       o.Scopes,
		Endpoint: oauth2.Endpoint{
			AuthURL:  endpoint.AuthURL,
			TokenURL: endpoint.TokenURL,
		},
	}
	return config
}

// refreshGroup coalesces concurrent refreshes of the same refresh token.
var refreshGroup = &refreshCoalescer{calls: make(map[string]*refreshCall)}

type refreshCoalescer struct {
	mu    sync.Mutex
	calls map[string]*refreshCall
}

type refreshCall struct {
	done  chan struct{}
	token *oauth2.Token
	err   error
	// settledAt lets the result be reused briefly, so requests that arrive just
	// after an exchange do not spend the rotated refresh token a second time.
	settledAt time.Time
}

// refreshResultTTL is how long a completed exchange is reused.
const refreshResultTTL = 30 * time.Second

func (c *refreshCoalescer) do(refreshToken string, exchange func() (*oauth2.Token, error)) (*oauth2.Token, error) {
	sum := sha256.Sum256([]byte(refreshToken))
	key := hex.EncodeToString(sum[:])

	c.mu.Lock()
	if call, ok := c.calls[key]; ok {
		c.mu.Unlock()
		<-call.done
		return call.token, call.err
	}
	call := &refreshCall{done: make(chan struct{})}
	c.calls[key] = call
	c.mu.Unlock()

	call.token, call.err = exchange()
	call.settledAt = time.Now()
	close(call.done)

	// Keep the result briefly for the requests already in flight behind this
	// one, then let the key go so a later refresh is a fresh exchange.
	time.AfterFunc(refreshResultTTL, func() {
		c.mu.Lock()
		if current, ok := c.calls[key]; ok && current == call {
			delete(c.calls, key)
		}
		c.mu.Unlock()
	})

	return call.token, call.err
}

// wantsHTML reports whether the request is a browser navigation, the only case
// where an authentication redirect makes sense.
func wantsHTML(r *http.Request) bool {
	if dest := r.Header.Get("Sec-Fetch-Dest"); dest != "" {
		return dest == "document" || dest == "iframe" || dest == "frame"
	}
	if r.Header.Get("X-Requested-With") == "XMLHttpRequest" {
		return false
	}
	return strings.Contains(r.Header.Get("Accept"), contentTypeHTML)
}

// verifyJWT validates a token's signature against the provider's JWKS and its
// registered claims. Only asymmetric algorithms are accepted, so a token cannot
// be forged by signing HS256 with a public key as the HMAC secret.
func verifyJWT(tokenStr, jwksURL, issuer, audience string) (jwt.MapClaims, error) {
	options := []jwt.ParserOption{
		jwt.WithValidMethods(asymmetricAlgorithms),
		jwt.WithExpirationRequired(),
	}
	if issuer != "" {
		options = append(options, jwt.WithIssuer(issuer))
	}
	if audience != "" {
		options = append(options, jwt.WithAudience(audience))
	}

	token, err := jwt.Parse(tokenStr, jwksKeyFunc(jwksURL), options...)
	if err != nil {
		return nil, err
	}
	if !token.Valid {
		return nil, errors.New("token is not valid")
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("invalid claims format")
	}
	return claims, nil
}

func jwksKeyFunc(jwksURL string) jwt.Keyfunc {
	return func(token *jwt.Token) (interface{}, error) {
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, errors.New("missing kid in token header")
		}
		keySet, err := fetchJWKS(jwksURL)
		if err != nil {
			return nil, err
		}
		return keySet.getKey(kid)
	}
}

// isJWT reports whether a token is a JWS the gateway could verify. Many
// providers (Google, GitHub, Facebook) issue opaque access tokens instead.
func isJWT(token string) bool {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return false
	}
	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return false
	}
	var decoded struct {
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(header, &decoded); err != nil {
		return false
	}
	return decoded.Alg != ""
}

// userInfoStore caches user info lookups across routes and requests.
var userInfoStore = &userInfoCache{entries: make(map[string]userInfoEntry)}

type userInfoCache struct {
	mu      sync.Mutex
	entries map[string]userInfoEntry
}

type userInfoEntry struct {
	claims    map[string]interface{}
	err       error
	expiresAt time.Time
}

func (c *userInfoCache) get(key string) (userInfoEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[key]
	if !ok || time.Now().After(entry.expiresAt) {
		return userInfoEntry{}, false
	}
	return entry, true
}

func (c *userInfoCache) put(key string, entry userInfoEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) >= maxUserInfoCacheEntries {
		now := time.Now()
		for k, e := range c.entries {
			if now.After(e.expiresAt) {
				delete(c.entries, k)
			}
		}
		if len(c.entries) >= maxUserInfoCacheEntries {
			c.entries = make(map[string]userInfoEntry)
		}
	}
	c.entries[key] = entry
}

// fetchUserInfo calls the provider's user info endpoint with the access token.
// A 2xx means the token is still valid and yields the user's claims; a 401 or
// 403 means it is not.
func fetchUserInfo(ctx context.Context, userInfoURL, accessToken string) (map[string]interface{}, error) {
	// Tokens are never used as cache keys directly.
	sum := sha256.Sum256([]byte(userInfoURL + "\x00" + accessToken))
	key := hex.EncodeToString(sum[:])

	if entry, ok := userInfoStore.get(key); ok {
		return mergeClaims(map[string]interface{}{}, entry.claims), entry.err
	}

	claims, err := requestUserInfo(ctx, userInfoURL, accessToken)
	ttl := userInfoCacheTTL
	if err != nil {
		ttl = userInfoNegativeTTL
	}
	userInfoStore.put(key, userInfoEntry{claims: claims, err: err, expiresAt: time.Now().Add(ttl)})
	return claims, err
}

func requestUserInfo(ctx context.Context, userInfoURL, accessToken string) (map[string]interface{}, error) {
	ctx, cancel := context.WithTimeout(ctx, userInfoRequestTimeout)
	defer cancel()

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, userInfoURL, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+accessToken)
	request.Header.Set("Accept", "application/json")

	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = response.Body.Close()
	}()

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("user info endpoint returned %d", response.StatusCode)
	}

	var claims map[string]interface{}
	if err := json.NewDecoder(io.LimitReader(response.Body, maxUserInfoBytes)).Decode(&claims); err != nil {
		return nil, fmt.Errorf("failed to decode user info response: %w", err)
	}
	return claims, nil
}
