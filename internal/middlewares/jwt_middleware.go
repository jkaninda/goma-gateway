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
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

func (jwtAuth *JwtAuth) AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Strip the keys the gateway owns before anything else, so a client
		// cannot supply them on a path this middleware does not guard.
		jwtAuth.Forward.Strip(r)

		if !isPathMatching(r.URL.Path, jwtAuth.Path, jwtAuth.Paths) {
			next.ServeHTTP(w, r)
			return
		}

		contentType := getContentType(r)
		authHeader, ok := validateHeaders(r, jwtAuth.Origins, w, r, contentType)
		if !ok {
			logger.Warn("Invalid or missing headers", "path", r.URL.Path)
			return
		}

		if !strings.HasPrefix(authHeader, "Bearer ") {
			logger.Warn("Authorization header missing Bearer prefix", "path", r.URL.Path)
			RespondWithError(w, r, http.StatusUnauthorized, "Missing Bearer prefix", jwtAuth.Origins, contentType)
			return
		}

		tokenStr := strings.TrimPrefix(authHeader, "Bearer ")

		keyFunc, err := jwtAuth.resolveKeyFunc()
		if err != nil {
			logger.Error("Failed to resolve JWT key function", "error", err)
			RespondWithError(w, r, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError), jwtAuth.Origins, contentType)
			return
		}

		token, err := jwt.Parse(tokenStr, keyFunc,
			jwt.WithValidMethods(jwtAuth.allowedAlgorithms()),
			jwt.WithAudience(jwtAuth.Audience),
			jwt.WithIssuer(jwtAuth.Issuer),
		)

		if err != nil || !token.Valid {
			logger.Warn("Invalid or expired JWT token", "error", err)
			RespondWithError(w, r, http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized), jwtAuth.Origins, contentType)
			return
		}

		if jwtAuth.ClaimsExpression != "" {
			valid, err := jwtAuth.validateJWTClaims(token)
			if err != nil {
				logger.Error("Failed to validate JWT claims", "error", err)
				RespondWithError(w, r, http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized), jwtAuth.Origins, contentType)
				return
			}
			if !valid {
				logger.Warn("JWT claims did not meet required expression")
				RespondWithError(w, r, http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized), jwtAuth.Origins, contentType)
				return
			}
		}

		if !jwtAuth.ForwardAuthorization {
			r.Header.Del("Authorization")
		}

		if jwtAuth.Forward.Enabled() {
			claims, ok := token.Claims.(jwt.MapClaims)
			if !ok {
				logger.Error("Failed to forward claims", "error", "invalid claims format")
				RespondWithError(w, r, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError), jwtAuth.Origins, contentType)
				return
			}
			jwtAuth.Forward.Apply(r, claims)
		}

		next.ServeHTTP(w, r)
	})
}

// hmacAlgorithms are the symmetric signing algorithms accepted for a shared
// Secret. asymmetricAlgorithms are the algorithms accepted for an RSA/EC public
// key (JWKS or RSA key); HMAC is deliberately excluded from this set so an
// attacker cannot forge a token by signing HS256 with the public key as the HMAC
// secret (the RS/HS algorithm-confusion attack).
var (
	hmacAlgorithms       = []string{"HS256", "HS384", "HS512"}
	asymmetricAlgorithms = []string{"RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512"}
)

// allowedAlgorithms returns the JWT signing algorithms accepted for this
// middleware, derived per-request (never a shared mutable global) and scoped to
// the configured key type. The key-source precedence mirrors resolveKeyFunc so
// the accepted algorithms always match the key actually used for verification.
// An explicit Algorithms list (or the deprecated single Algo) overrides the
// defaults.
func (jwtAuth *JwtAuth) allowedAlgorithms() []string {
	if len(jwtAuth.Algorithms) != 0 {
		return jwtAuth.Algorithms
	}
	if jwtAuth.Algo != "" { // Deprecated: superseded by Algorithms.
		return []string{jwtAuth.Algo}
	}
	switch {
	case jwtAuth.JwksUrl != "":
		return asymmetricAlgorithms
	case jwtAuth.Secret != "":
		return hmacAlgorithms
	case jwtAuth.JwksFile != nil && len(jwtAuth.JwksFile.Keys) != 0:
		return asymmetricAlgorithms
	case jwtAuth.RsaKey != nil:
		return asymmetricAlgorithms
	default:
		return asymmetricAlgorithms
	}
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
func (jwtAuth *JwtAuth) resolveKeyFunc() (jwt.Keyfunc, error) {
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

// Updated validateJWTClaims method
func (jwtAuth *JwtAuth) validateJWTClaims(token *jwt.Token) (bool, error) {
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return false, fmt.Errorf("invalid claims format")
	}

	// Use expression-based validation if available
	if jwtAuth.ClaimsExpression != "" {
		// Parse expression if not already cached
		if jwtAuth.parsedExpression == nil {
			expr, err := ParseExpression(jwtAuth.ClaimsExpression)
			if err != nil {
				return false, fmt.Errorf("failed to parse claims expression: %v", err)
			}
			jwtAuth.parsedExpression = expr
		}

		result, err := jwtAuth.parsedExpression.Evaluate(claims)
		if err != nil {
			return false, fmt.Errorf("expression evaluation failed: %v", err)
		}
		return result, nil
	}

	return true, nil // No claims validation configured
}
