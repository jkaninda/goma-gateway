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
	"errors"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jkaninda/goma-gateway/util"
	"golang.org/x/oauth2"
	"net/http"
	"time"
)

func (oauth Oauth) AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip paths that don’t match configured ones
		if !isPathMatching(r.URL.Path, oauth.Path, oauth.Paths) {
			next.ServeHTTP(w, r)
			return
		}

		// Always skip the callback path
		callbackPath := util.UrlParsePath(oauth.RedirectURL)
		if r.URL.Path == callbackPath {
			next.ServeHTTP(w, r)
			return
		}

		oauthConf := oauth2Config(oauth)
		authRedirectURL := oauthConf.AuthCodeURL(oauth.State)
		ctx := context.Background()
		jwksURL := oauth.Endpoint.JwksURL
		// Retrieve tokens from cookies
		accessTokenCookie, err := r.Cookie("access_token")
		refreshTokenCookie, _ := r.Cookie("refresh_token")
		if err != nil {
			http.Redirect(w, r, authRedirectURL, http.StatusTemporaryRedirect)
			return
		}

		accessToken := accessTokenCookie.Value
		refreshToken := ""
		if refreshTokenCookie != nil {
			refreshToken = refreshTokenCookie.Value
		}

		// Check token expiry (JWKS verification if URL is provided)
		isExpired := tokenIsExpired(accessToken, jwksURL)
		if isExpired {
			logger.Info("Access token expired, attempting refresh...")

			t := &oauth2.Token{
				AccessToken:  accessToken,
				RefreshToken: refreshToken,
				Expiry:       time.Now().Add(-1 * time.Minute), // Simulate expiry
			}

			ts := oauthConf.TokenSource(ctx, t)
			newToken, err := ts.Token()
			if err != nil {
				http.Redirect(w, r, authRedirectURL, http.StatusTemporaryRedirect)
				return
			}

			http.SetCookie(w, &http.Cookie{
				Name:     "access_token",
				Value:    newToken.AccessToken,
				Path:     oauth.CookiePath,
				HttpOnly: true,
			})

			if newToken.RefreshToken != "" {
				http.SetCookie(w, &http.Cookie{
					Name:     "refresh_token",
					Value:    newToken.RefreshToken,
					Path:     oauth.CookiePath,
					HttpOnly: true,
				})
			}
		}

		// Token valid or refreshed: continue
		next.ServeHTTP(w, r)
	})
}

// tokenIsExpired validates the JWT against the JWKS (if provided) and checks 'exp'.
func tokenIsExpired(tokenStr, jwksURL string) bool {
	var keyFunc jwt.Keyfunc

	if jwksURL != "" {
		// Use keyFunc that fetches public key from JWKS
		keyFunc = func(token *jwt.Token) (interface{}, error) {
			kid, ok := token.Header["kid"].(string)
			if !ok {
				return nil, errors.New("missing kid in token header")
			}

			keySet, err := fetchJWKS(jwksURL)
			if err != nil {
				return nil, err
			}

			key, err := keySet.getKey(kid)
			if err != nil {
				return nil, err
			}

			return key, nil
		}
	} else {
		// If no JWKS, parse without verifying signature
		token, _, err := jwt.NewParser().ParseUnverified(tokenStr, jwt.MapClaims{})
		if err != nil {
			return true
		}
		return isExpiredFromClaims(token.Claims)
	}

	// Validate and parse the token
	token, err := jwt.Parse(tokenStr, keyFunc)
	if err != nil || !token.Valid {
		return true
	}

	return isExpiredFromClaims(token.Claims)
}

func isExpiredFromClaims(claims jwt.Claims) bool {
	mapClaims, ok := claims.(jwt.MapClaims)
	if !ok {
		return true
	}
	expClaim, ok := mapClaims["exp"].(float64)
	if !ok {
		return true
	}
	expTime := time.Unix(int64(expClaim), 0)
	return time.Now().After(expTime)
}
