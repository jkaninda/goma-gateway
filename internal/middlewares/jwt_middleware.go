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

func (jwtAuth *JwtAuth) AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

		if jwtAuth.Algo != "" {
			jwtAlgo = []string{jwtAuth.Algo}
		}

		token, err := jwt.Parse(tokenStr, keyFunc,
			jwt.WithValidMethods(jwtAlgo),
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

		if jwtAuth.ForwardHeaders != nil {
			if err := jwtAuth.forwardHeadersFromClaims(token, r.Header); err != nil {
				logger.Error("Failed to forward headers from claims", "error", err)
				RespondWithError(w, r, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError), jwtAuth.Origins, contentType)
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

// forwardHeadersFromClaims extracts values from JWT claims and sets them as HTTP headers
func (jwtAuth *JwtAuth) forwardHeadersFromClaims(token *jwt.Token, headers map[string][]string) error {
	// Get claims as MapClaims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return fmt.Errorf("invalid claims format")
	}
	// Process each header mapping
	for headerName, claimPath := range jwtAuth.ForwardHeaders {
		// Extract claim value using nested key traversal with dot notation support
		claimValue, err := jwtAuth.extractNestedClaimValue(claims, claimPath)
		if err != nil {
			logger.Error("Warning: Could not extract claim", "claimPath", claimPath, "error", err)
			continue
		}

		// Convert claim value to string
		headerValue := jwtAuth.formatHeaderValue(claimValue)
		if headerValue == "" {
			continue // Skip empty values
		}

		// Set the header
		if headers == nil {
			headers = make(map[string][]string)
		}
		headers[headerName] = []string{headerValue}
	}

	return nil
}

// extractNestedClaimValue extracts a value from JWT claims using dot notation for nested keys
func (jwtAuth *JwtAuth) extractNestedClaimValue(claims jwt.MapClaims, claimKey string) (interface{}, error) {
	// Handle nested keys using dot notation (e.g., "user.profile.email")
	keys := strings.Split(claimKey, ".")
	var current interface{} = map[string]interface{}(claims)

	// Traverse nested keys
	for i, k := range keys {
		if m, ok := current.(map[string]interface{}); ok {
			if val, exists := m[k]; exists {
				current = val
			} else {
				return nil, fmt.Errorf("claim key '%s' not found at path '%s'", k, strings.Join(keys[:i+1], "."))
			}
		} else {
			return nil, fmt.Errorf("cannot traverse claim path at key '%s' (expected object, got %T)", k, current)
		}
	}

	return current, nil
}

// formatHeaderValue converts a claim value to a header string
func (jwtAuth *JwtAuth) formatHeaderValue(claimValue interface{}) string {
	// Convert claim value to string
	switch cv := claimValue.(type) {
	case string:
		return cv
	case float64:
		return fmt.Sprintf("%.0f", cv)
	case bool:
		return fmt.Sprintf("%t", cv)
	case []interface{}:
		// Join array values with comma
		var strValues []string
		for _, v := range cv {
			if vStr, ok := v.(string); ok {
				strValues = append(strValues, vStr)
			} else {
				strValues = append(strValues, fmt.Sprintf("%v", v))
			}
		}
		return strings.Join(strValues, ",")
	default:
		return fmt.Sprintf("%v", cv)
	}
}
