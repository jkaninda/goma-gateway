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
	"github.com/jkaninda/goma-gateway/util"
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

// oauthSession holds the tokens carried by the browser's cookies.
type oauthSession struct {
	accessToken  string
	refreshToken string
	idToken      string
}

func (oauth *Oauth) AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		oauth.Forward.Strip(r)

		// Skip paths that don’t match configured ones
		if !isPathMatching(r.URL.Path, oauth.Path, oauth.Paths) {
			next.ServeHTTP(w, r)
			return
		}

		// Always skip the callback path
		if r.URL.Path == util.UrlParsePath(oauth.RedirectURL) {
			next.ServeHTTP(w, r)
			return
		}

		authRedirectURL := oauth2Config(oauth).AuthCodeURL(oauth.State)
		ctx := r.Context()

		session, ok := readOauthSession(r)
		if !ok {
			oauth.challenge(w, r, authRedirectURL, "no session cookie")
			return
		}

		claims, err := oauth.verify(ctx, session)
		if err != nil {
			if errors.Is(err, errNoVerifier) {
				logger.Error("OAuth middleware is not configured to verify tokens, rejecting request",
					"path", r.URL.Path, "error", err)
				RespondWithError(w, r, http.StatusInternalServerError,
					http.StatusText(http.StatusInternalServerError), oauth.Origins, getContentType(r))
				return
			}
			logger.Debug("Access token rejected, attempting refresh", "path", r.URL.Path, "error", err)

			refreshed, refreshErr := oauth.refresh(ctx, session)
			if refreshErr != nil {
				oauth.challenge(w, r, authRedirectURL, refreshErr.Error())
				return
			}
			claims, err = oauth.verify(ctx, refreshed)
			if err != nil {
				oauth.challenge(w, r, authRedirectURL, err.Error())
				return
			}
			writeOauthSession(w, r, oauth.CookiePath, refreshed)
			session = refreshed
		}

		oauth.Forward.Apply(r, claims)
		oauth.Forward.ForwardTokens(r, session.accessToken, session.idToken)

		next.ServeHTTP(w, r)
	})
}

// verify establishes that the session is genuine and returns the claims to
// project upstream.
func (oauth *Oauth) verify(ctx context.Context, session oauthSession) (map[string]interface{}, error) {
	sources := oauth.claimsSources()

	var idClaims, accessClaims, userInfoClaims map[string]interface{}
	verified := false

	// The ID token is the only token OIDC defines as an identity assertion, and
	// its audience must be this client — otherwise a token minted for another
	// application of the same provider would be accepted here.
	if session.idToken != "" && oauth.Endpoint.JwksURL != "" {
		claims, err := verifyJWT(session.idToken, oauth.Endpoint.JwksURL, oauth.Issuer, oauth.ClientID)
		if err != nil {
			return nil, fmt.Errorf("id token verification failed: %w", err)
		}
		idClaims = claims
		verified = true
	}

	switch {
	case oauth.Endpoint.JwksURL != "" && isJWT(session.accessToken):
		claims, err := verifyJWT(session.accessToken, oauth.Endpoint.JwksURL, oauth.Issuer, oauth.Audience)
		if err != nil {
			return nil, fmt.Errorf("access token verification failed: %w", err)
		}
		accessClaims = claims
		verified = true

	case oauth.Endpoint.UserInfoURL != "":
		// Opaque access tokens carry no verifiable claims; the provider's user
		// info endpoint is what says whether the token is still valid.
		claims, err := oauth.fetchUserInfo(ctx, session.accessToken)
		if err != nil {
			return nil, fmt.Errorf("user info verification failed: %w", err)
		}
		userInfoClaims = claims
		verified = true

	default:
		if !verified {
			return nil, errNoVerifier
		}
	}

	// User info was not needed to verify the session, but may still be the only
	// place a claim we forward lives.
	if userInfoClaims == nil && oauth.Endpoint.UserInfoURL != "" &&
		slices.Contains(sources, ClaimSourceUserInfo) && oauth.Forward.Enabled() {
		claims, err := oauth.fetchUserInfo(ctx, session.accessToken)
		if err != nil {
			logger.Warn("Failed to fetch user info, claims not forwarded from it", "error", err)
		} else {
			userInfoClaims = claims
		}
	}

	claims := map[string]interface{}{}
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

// refresh exchanges the refresh token for a new session.
//
// Each request refreshes on its own; with a provider that rotates refresh
// tokens, concurrent requests can race. A shared session store removes that,
// and is tracked separately.
func (oauth *Oauth) refresh(ctx context.Context, session oauthSession) (oauthSession, error) {
	if session.refreshToken == "" {
		return session, errors.New("session expired and no refresh token is available")
	}

	source := oauth2Config(oauth).TokenSource(ctx, &oauth2.Token{
		AccessToken:  session.accessToken,
		RefreshToken: session.refreshToken,
		Expiry:       time.Now().Add(-1 * time.Minute), // Force the exchange.
	})
	token, err := source.Token()
	if err != nil {
		return session, fmt.Errorf("token refresh failed: %w", err)
	}

	refreshed := oauthSession{
		accessToken:  token.AccessToken,
		refreshToken: token.RefreshToken,
		idToken:      session.idToken,
	}
	if refreshed.refreshToken == "" {
		refreshed.refreshToken = session.refreshToken
	}
	if idToken, ok := token.Extra("id_token").(string); ok && idToken != "" {
		refreshed.idToken = idToken
	}
	return refreshed, nil
}

// challenge sends the caller to the identity provider, but only when the caller
// is a browser navigating: an API client or an XHR needs a 401 it can act on,
// not a redirect to a login page it cannot render.
func (oauth *Oauth) challenge(w http.ResponseWriter, r *http.Request, authURL, reason string) {
	logger.Debug("OAuth challenge", "path", r.URL.Path, "client_ip", RealIP(r), "reason", reason)

	if r.Method == http.MethodGet && wantsHTML(r) {
		http.Redirect(w, r, authURL, http.StatusFound)
		return
	}
	w.Header().Set("WWW-Authenticate", `Bearer realm="oauth", error="invalid_token"`)
	RespondWithError(w, r, http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized),
		oauth.Origins, getContentType(r))
}

func (oauth *Oauth) claimsSources() []string {
	if len(oauth.ClaimsSource) == 0 {
		return DefaultClaimsSource
	}
	return oauth.ClaimsSource
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
	return strings.Contains(r.Header.Get("Accept"), "text/html")
}

// readOauthSession reads the session tokens from the request cookies.
func readOauthSession(r *http.Request) (oauthSession, bool) {
	accessToken, err := r.Cookie(GomaAccessToken)
	if err != nil || accessToken.Value == "" {
		return oauthSession{}, false
	}
	session := oauthSession{accessToken: accessToken.Value}
	if refreshToken, err := r.Cookie(GomaRefreshToken); err == nil {
		session.refreshToken = refreshToken.Value
	}
	if idToken, err := r.Cookie(GomaIDToken); err == nil {
		session.idToken = idToken.Value
	}
	return session, true
}

// writeOauthSession stores the session tokens as hardened cookies.
func writeOauthSession(w http.ResponseWriter, r *http.Request, cookiePath string, session oauthSession) {
	http.SetCookie(w, NewAuthCookie(r, GomaAccessToken, session.accessToken, cookiePath))
	if session.refreshToken != "" {
		http.SetCookie(w, NewAuthCookie(r, GomaRefreshToken, session.refreshToken, cookiePath))
	}
	if session.idToken != "" {
		http.SetCookie(w, NewAuthCookie(r, GomaIDToken, session.idToken, cookiePath))
	}
}

// NewAuthCookie builds a session cookie for the OAuth flow with the attributes
// a browser needs to keep it safe: HttpOnly, SameSite=Lax so it survives the
// provider's cross-site callback redirect without being sent on cross-site
// POSTs, and Secure whenever the request arrived over TLS.
//
// The cookies are session cookies: the tokens they carry are only usable while
// the provider still honours them, and a browser restart should not leave a
// long-lived credential on disk.
func NewAuthCookie(r *http.Request, name, value, path string) *http.Cookie {
	if path == "" {
		path = "/"
	}
	return &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     path,
		HttpOnly: true,
		Secure:   scheme(r) == "https",
		SameSite: http.SameSiteLaxMode,
	}
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
func (oauth *Oauth) fetchUserInfo(ctx context.Context, accessToken string) (map[string]interface{}, error) {
	// Tokens are never used as cache keys directly.
	sum := sha256.Sum256([]byte(oauth.Endpoint.UserInfoURL + "\x00" + accessToken))
	key := hex.EncodeToString(sum[:])

	if entry, ok := userInfoStore.get(key); ok {
		return entry.claims, entry.err
	}

	claims, err := requestUserInfo(ctx, oauth.Endpoint.UserInfoURL, accessToken)
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
