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
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

const (
	// flowCookieName holds the state of a login in progress.
	flowCookieName = "goma_oidc_flow"
	// flowTTL bounds how long a user may take to come back from the provider.
	flowTTL = 10 * time.Minute
	// stateBytes and nonceBytes size the CSRF and replay guards.
	stateBytes = 32
	nonceBytes = 32
)

// flowState is what the gateway must remember between sending a user to the
// provider and the provider sending them back. It travels in a sealed cookie,
// so no server-side state is needed for a login in progress.
type flowState struct {
	State    string `json:"s"`
	Nonce    string `json:"n"`
	Verifier string `json:"v,omitempty"`
	ReturnTo string `json:"r,omitempty"`
	IssuedAt int64  `json:"iat"`
}

// startAuth sends a browser to the provider, remembering where it came from.
// Anything that is not a browser navigation gets a 401 it can act on instead of
// a redirect to a login page it cannot render.
func (o *OIDC) startAuth(w http.ResponseWriter, r *http.Request, endpoint OauthEndpoint, reason string) {
	logger.Debug("Starting OIDC login", "path", r.URL.Path, "client_ip", RealIP(r), "reason", reason)

	if r.Method != http.MethodGet || !wantsHTML(r) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="oidc", error="invalid_token"`)
		RespondWithError(w, r, http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized),
			o.Origins, getContentType(r))
		return
	}

	state, err := randomToken(stateBytes)
	if err != nil {
		logger.Error("Failed to generate the login state", "error", err)
		RespondWithError(w, r, http.StatusInternalServerError,
			http.StatusText(http.StatusInternalServerError), o.Origins, getContentType(r))
		return
	}
	nonce, err := randomToken(nonceBytes)
	if err != nil {
		logger.Error("Failed to generate the login nonce", "error", err)
		RespondWithError(w, r, http.StatusInternalServerError,
			http.StatusText(http.StatusInternalServerError), o.Origins, getContentType(r))
		return
	}

	flow := &flowState{
		State:    state,
		Nonce:    nonce,
		ReturnTo: r.URL.RequestURI(),
		IssuedAt: time.Now().Unix(),
	}

	options := []oauth2.AuthCodeOption{oauth2.SetAuthURLParam("nonce", nonce)}
	if !o.DisablePKCE {
		// The verifier never leaves the gateway; only its hash goes to the
		// provider, so an intercepted authorization code is useless on its own.
		flow.Verifier = oauth2.GenerateVerifier()
		options = append(options, oauth2.S256ChallengeOption(flow.Verifier))
	}

	if err := o.writeFlowCookie(w, r, flow); err != nil {
		logger.Error("Failed to store the login state", "error", err)
		RespondWithError(w, r, http.StatusInternalServerError,
			http.StatusText(http.StatusInternalServerError), o.Origins, getContentType(r))
		return
	}

	http.Redirect(w, r, o.oauth2Config(endpoint).AuthCodeURL(state, options...), http.StatusFound)
}

// CallbackHandler completes the login: it checks the request really belongs to
// the flow this browser started, exchanges the code, verifies the ID token, and
// opens a session.
func (o *OIDC) CallbackHandler(w http.ResponseWriter, r *http.Request) {
	contentType := getContentType(r)
	ctx := r.Context()

	endpoint, _, err := o.endpoints(ctx)
	if err != nil {
		logger.Error("OIDC provider metadata is unavailable", "issuer", o.Issuer, "error", err)
		RespondWithError(w, r, http.StatusInternalServerError,
			http.StatusText(http.StatusInternalServerError), o.Origins, contentType)
		return
	}

	flow, err := o.readFlowCookie(r)
	o.clearFlowCookie(w, r)
	if err != nil {
		logger.Warn("OIDC callback without a valid login state",
			"client_ip", RealIP(r), "error", err)
		RespondWithError(w, r, http.StatusBadRequest, "invalid or expired login state", o.Origins, contentType)
		return
	}

	query := r.URL.Query()
	if providerError := query.Get("error"); providerError != "" {
		logger.Warn("Identity provider refused the login",
			"error", providerError, "description", query.Get("error_description"))
		RespondWithError(w, r, http.StatusForbidden, "the identity provider refused the login",
			o.Origins, contentType)
		return
	}

	// The state ties this callback to the flow this browser started, which is
	// what stops an attacker from having their own code redeemed in a victim's
	// session. It is compared in constant time.
	if subtle.ConstantTimeCompare([]byte(query.Get("state")), []byte(flow.State)) != 1 {
		logger.Warn("OIDC callback state mismatch", "client_ip", RealIP(r))
		RespondWithError(w, r, http.StatusBadRequest, "invalid state", o.Origins, contentType)
		return
	}

	code := query.Get("code")
	if code == "" {
		RespondWithError(w, r, http.StatusBadRequest, "missing code", o.Origins, contentType)
		return
	}

	options := []oauth2.AuthCodeOption{}
	if flow.Verifier != "" {
		options = append(options, oauth2.VerifierOption(flow.Verifier))
	}
	token, err := o.oauth2Config(endpoint).Exchange(ctx, code, options...)
	if err != nil {
		logger.Error("Failed to exchange the authorization code", "error", err)
		RespondWithError(w, r, http.StatusBadGateway, "failed to exchange the authorization code",
			o.Origins, contentType)
		return
	}

	session := &Session{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		IssuedAt:     time.Now().Unix(),
		LastSeen:     time.Now().Unix(),
	}

	if idToken, ok := token.Extra("id_token").(string); ok && idToken != "" {
		session.IDToken = idToken

		if endpoint.JwksURL != "" {
			claims, err := verifyJWT(idToken, endpoint.JwksURL, o.Issuer, o.ClientID)
			if err != nil {
				logger.Error("ID token verification failed", "error", err)
				RespondWithError(w, r, http.StatusForbidden, "id token verification failed",
					o.Origins, contentType)
				return
			}
			// The nonce ties the ID token to this login, so one captured
			// elsewhere cannot be replayed into this session.
			if claimNonce, _ := claims["nonce"].(string); claimNonce != flow.Nonce {
				logger.Warn("ID token nonce mismatch", "client_ip", RealIP(r))
				RespondWithError(w, r, http.StatusForbidden, "id token nonce mismatch",
					o.Origins, contentType)
				return
			}
			session.Claims = claims
		}
	}

	// Claims are captured once here so a provider that only returns them at
	// sign-in — or only from user info — does not have to be asked again.
	if endpoint.UserInfoURL != "" && slices.Contains(o.claimsSources(), ClaimSourceUserInfo) {
		if claims, err := fetchUserInfo(ctx, endpoint.UserInfoURL, token.AccessToken); err == nil {
			// User info first, then the ID token's claims on top: the ID token
			// is the provider's identity assertion and outranks it.
			merged := mergeClaims(map[string]interface{}{}, claims)
			session.Claims = mergeClaims(merged, session.Claims)
		} else {
			logger.Warn("Failed to fetch user info at sign-in", "error", err)
		}
	}

	if !o.authorized(claimsFromMap(session.Claims)) {
		logger.Warn("User signed in but is not authorized for this route",
			"client_ip", RealIP(r), "expression", o.ClaimsExpression)
		RespondWithError(w, r, http.StatusForbidden, http.StatusText(http.StatusForbidden),
			o.Origins, contentType)
		return
	}

	r = o.store.Renew(w, r)

	if err := o.store.Save(w, r, session); err != nil {
		logger.Error("Failed to open the session", "error", err)
		RespondWithError(w, r, http.StatusInternalServerError,
			http.StatusText(http.StatusInternalServerError), o.Origins, contentType)
		return
	}

	http.Redirect(w, r, o.postLoginDestination(flow), http.StatusSeeOther)
}

// LogoutHandler ends the session, and asks the provider to end its own when it
// supports RP-initiated logout.
func (o *OIDC) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	session, err := o.store.Load(r)
	o.store.Clear(w, r)
	o.clearFlowCookie(w, r)

	_, endSessionEndpoint, endpointErr := o.endpoints(r.Context())

	destination := o.PostLogoutRedirect
	if destination == "" {
		destination = "/"
	}

	if endpointErr == nil && endSessionEndpoint != "" && err == nil && session.IDToken != "" {
		parsed, parseErr := url.Parse(endSessionEndpoint)
		if parseErr == nil {
			query := parsed.Query()
			query.Set("id_token_hint", session.IDToken)
			if absolute := o.absoluteURL(r, destination); absolute != "" {
				query.Set("post_logout_redirect_uri", absolute)
			}
			parsed.RawQuery = query.Encode()
			http.Redirect(w, r, parsed.String(), http.StatusSeeOther)
			return
		}
		logger.Warn("Unusable end session endpoint", "endpoint", endSessionEndpoint, "error", parseErr)
	}

	http.Redirect(w, r, destination, http.StatusSeeOther)
}

// postLoginDestination is where the user lands after signing in: the URL they
// originally asked for, unless the route pins one.
func (o *OIDC) postLoginDestination(flow *flowState) string {
	if o.PostLoginRedirect != "" {
		return o.PostLoginRedirect
	}
	if returnTo := safeReturnTo(flow.ReturnTo); returnTo != "" {
		return returnTo
	}
	if o.Path != "" {
		return o.Path
	}
	return "/"
}

// safeReturnTo accepts only a path on this gateway. Anything that could send
// the browser to another origin after a successful login is discarded: that is
// the classic open-redirect handed out by a login endpoint.
func safeReturnTo(candidate string) string {
	if candidate == "" || !strings.HasPrefix(candidate, "/") {
		return ""
	}
	// "//host" and "/\host" are both read as protocol-relative URLs.
	if strings.HasPrefix(candidate, "//") || strings.HasPrefix(candidate, "/\\") {
		return ""
	}
	parsed, err := url.Parse(candidate)
	if err != nil || parsed.Host != "" || parsed.Scheme != "" {
		return ""
	}
	return candidate
}

// absoluteURL turns a path on this gateway into the absolute URL a provider
// needs for post_logout_redirect_uri.
func (o *OIDC) absoluteURL(r *http.Request, path string) string {
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		return path
	}
	if safeReturnTo(path) == "" || r.Host == "" {
		return ""
	}
	return scheme(r) + "://" + r.Host + path
}

func (o *OIDC) writeFlowCookie(w http.ResponseWriter, r *http.Request, flow *flowState) error {
	payload, err := json.Marshal(flow)
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     flowCookieName,
		Value:    o.flowSealer.seal(payload),
		Path:     o.flowCookiePath(),
		MaxAge:   int(flowTTL.Seconds()),
		HttpOnly: true,
		Secure:   scheme(r) == schemeHTTPS,
		// The provider's callback is a cross-site navigation, so the cookie
		// must survive it; Lax does, Strict does not.
		SameSite: http.SameSiteLaxMode,
	})
	return nil
}

func (o *OIDC) readFlowCookie(r *http.Request) (*flowState, error) {
	cookie, err := r.Cookie(flowCookieName)
	if err != nil {
		return nil, err
	}
	payload, err := o.flowSealer.open(cookie.Value)
	if err != nil {
		return nil, err
	}
	flow := &flowState{}
	if err := json.Unmarshal(payload, flow); err != nil {
		return nil, err
	}
	if flow.State == "" {
		return nil, errNoSession
	}
	if time.Since(time.Unix(flow.IssuedAt, 0)) > flowTTL {
		return nil, errNoSession
	}
	return flow, nil
}

func (o *OIDC) clearFlowCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     flowCookieName,
		Value:    "",
		Path:     o.flowCookiePath(),
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   scheme(r) == schemeHTTPS,
		SameSite: http.SameSiteLaxMode,
	})
}

// flowCookiePath scopes the flow cookie so it is sent both to the guarded paths
// and to the callback, which may sit outside them.
func (o *OIDC) flowCookiePath() string {
	if o.Session.CookiePath != "" {
		return o.Session.CookiePath
	}
	return "/"
}
