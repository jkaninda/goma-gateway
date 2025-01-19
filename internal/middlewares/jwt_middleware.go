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
	"github.com/golang-jwt/jwt"
	"github.com/jkaninda/goma-gateway/pkg/logger"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"net/http"
)

// AuthMiddleware authenticates the client using JWT
func (jwtAuth JwtAuth) AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger.Info("JWT")
		contentType := r.Header.Get("Content-Type")
		if isPathMatching(r.URL.Path, jwtAuth.Path, jwtAuth.Paths) {
			// Get the token from the Authorization header
			authHeader, valid := validateHeaders(r, jwtAuth.Origins, w, r, contentType)
			if !valid {
				return
			}
			tokenStr := authHeader[7:]

			var keyFunc jwt.Keyfunc

			if jwtAuth.JwksUrl != "" {
				// Fetch JWK Set
				set, err := jwk.Fetch(r.Context(), jwtAuth.JwksUrl)
				if err != nil {
					logger.Error("Failed to fetch JWK set: %v", err)
					RespondWithError(w, r, http.StatusInternalServerError, fmt.Sprintf("%d %s", http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError)), jwtAuth.Origins, contentType)
					return
				}
				// Define key function for JWK
				keyFunc = func(token *jwt.Token) (interface{}, error) {
					kid, ok := token.Header["kid"].(string)
					if !ok {
						return nil, fmt.Errorf("kid not found in token header")
					}

					key, found := set.LookupKeyID(kid)
					if !found {
						return nil, fmt.Errorf("key with kid %q not found", kid)
					}

					var rawKey interface{}
					if err = key.Raw(&rawKey); err != nil {
						return nil, fmt.Errorf("failed to extract raw key: %w", err)
					}
					return rawKey, nil
				}
			} else if jwtAuth.Secret != "" {
				// Define key function for static secret
				keyFunc = func(token *jwt.Token) (interface{}, error) {
					return []byte(jwtAuth.Secret), nil
				}
			} else if jwtAuth.RsaKey != nil {
				// Define key function for RSA public key
				keyFunc = func(token *jwt.Token) (interface{}, error) {
					return jwtAuth.RsaKey, nil
				}
			} else {
				logger.Error("No jwksURL, secret, or key provided")
				RespondWithError(w, r, http.StatusInternalServerError, fmt.Sprintf("%d %s", http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError)), jwtAuth.Origins, contentType)

				return
			}

			// Parse and validate JWT
			token, err := jwt.Parse(tokenStr, keyFunc)
			if err != nil {
				RespondWithError(w, r, http.StatusUnauthorized, fmt.Sprintf("%d %s", http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized)), jwtAuth.Origins, contentType)
				return
			}

			// Optional: Validate claims
			if !token.Valid {
				logger.Error("invalid token")
				RespondWithError(w, r, http.StatusUnauthorized, fmt.Sprintf("%d %s", http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized)), jwtAuth.Origins, contentType)
				return
			}
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
