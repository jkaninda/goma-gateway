/*
Copyright 2024 Jonas Kaninda

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package middlewares

import (
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"net/http"
	"strings"
)

func (jwtAuth JwtAuth) AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		if !isPathMatching(r.URL.Path, jwtAuth.Path, jwtAuth.Paths) {
			next.ServeHTTP(w, r)
			return
		}
		contentType := r.Header.Get("Content-Type")
		authHeader, ok := validateHeaders(r, jwtAuth.Origins, w, r, contentType)
		if !ok {
			return
		}

		if !strings.HasPrefix(authHeader, "Bearer ") {
			RespondWithError(w, r, http.StatusUnauthorized, "Missing Bearer prefix", jwtAuth.Origins, contentType)
			return
		}

		tokenStr := strings.TrimPrefix(authHeader, "Bearer ")

		keyFunc, err := jwtAuth.resolveKeyFunc()
		if err != nil {
			logger.Error("Failed to resolve key function", "error", err)
			RespondWithError(w, r, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError), jwtAuth.Origins, contentType)
			return
		}
		if jwtAuth.Algo != "" {
			jwtAlgo = []string{jwtAuth.Algo}
		}
		token, err := jwt.Parse(tokenStr, keyFunc, jwt.WithValidMethods(jwtAlgo), jwt.WithAudience(jwtAuth.Audience), jwt.WithIssuer(jwtAuth.Issuer))
		if err != nil {
			logger.Warn("Invalid token", "error", err)
			RespondWithError(w, r, http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized), jwtAuth.Origins, contentType)
			return
		}
		if !token.Valid {
			logger.Warn("Token is invalid")
			RespondWithError(w, r, http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized), jwtAuth.Origins, contentType)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// validateHeaders checks if the required headers are present in the request
func validateHeaders(r *http.Request, origins []string, w http.ResponseWriter, req *http.Request, contentType string) (string, bool) {
	authHeader := r.Header.Get("Authorization")

	if authHeader == "" {
		logger.Error("Proxy error, missing Authorization")
		if allowedOrigin(origins, r.Header.Get("Origin")) {
			w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
		}
		RespondWithError(w, req, http.StatusUnauthorized, fmt.Sprintf("%d %s", http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized)), origins, contentType)
		return authHeader, false
	}

	return authHeader, true
}
func (jwtAuth JwtAuth) resolveKeyFunc() (jwt.Keyfunc, error) {
	if jwtAuth.JwksUrl != "" {
		logger.Debug("Using JwksUrl ", "url", jwtAuth.JwksUrl)
		// Manual JWKS fetch
		return func(token *jwt.Token) (interface{}, error) {
			kid, ok := token.Header["kid"].(string)
			if !ok {
				return nil, fmt.Errorf("missing 'kid' in JWT header")
			}
			jwks, err := fetchJWKS(jwtAuth.JwksUrl)
			if err != nil {
				return nil, err
			}
			return jwks.getKey(kid)
		}, nil
	}

	if jwtAuth.Secret != "" {
		logger.Debug("Using Secret ", "secret", "***")
		return func(token *jwt.Token) (interface{}, error) {
			return []byte(jwtAuth.Secret), nil
		}, nil
	}
	if len(jwtAuth.JwksFile.Keys) != 0 {
		logger.Debug("Using JWKS File", "file", "***")
		return func(token *jwt.Token) (interface{}, error) {
			kid, ok := token.Header["kid"].(string)
			if !ok {
				return nil, fmt.Errorf("missing 'kid' in JWT header")
			}
			return jwtAuth.JwksFile.getKey(kid)
		}, nil
	}
	if jwtAuth.RsaKey != nil {
		logger.Debug("Using RsaKey", "key", "***")
		return func(token *jwt.Token) (interface{}, error) {
			return jwtAuth.RsaKey, nil
		}, nil
	}

	return nil, fmt.Errorf("no JWT secret, RSA key, or JWKS URL configured")
}
