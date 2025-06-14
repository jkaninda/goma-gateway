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
		if err != nil || !token.Valid {
			logger.Warn("Invalid or expired token", "error", err)
			RespondWithError(w, r, http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized), jwtAuth.Origins, contentType)
			return
		}

		if jwtAuth.Claims != nil {
			if ok, err = jwtAuth.validateJWTClaims(token); !ok {
				logger.Warn("Error validating claims", "error", err)
				RespondWithError(w, r, http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized), jwtAuth.Origins, contentType)
				return
			}
		}
		if !jwtAuth.ForwardAuthorization {
			r.Header.Del("Authorization")
		}
		if jwtAuth.ForwardHeaders != nil {
			err = jwtAuth.forwardHeadersFromClaims(token, r.Header)
			if err != nil {

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

func (jwtAuth JwtAuth) validateJWTClaims(token *jwt.Token) (bool, error) {
	// Get claims as MapClaims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return false, fmt.Errorf("invalid claims format")
	}

	// Validate each required claim
	for key, expectedValue := range jwtAuth.Claims {
		// Handle nested keys
		keys := strings.Split(key, ".")
		var current interface{} = map[string]interface{}(claims)
		var found bool

		// Traverse nested keys
		for _, k := range keys {
			// logger.info("Validating claims", "key", k)

			if m, ok := current.(map[string]interface{}); ok {
				if val, exists := m[k]; exists {
					current = val
					found = true
				} else {
					found = false
					break
				}
			} else {
				found = false
				break
			}
		}

		if !found {
			return false, fmt.Errorf("claim '%s' not found", key)
		}

		// Check the value
		switch ev := expectedValue.(type) {
		case string:
			// For string values, do direct comparison
			if cv, ok := current.(string); !ok || cv != ev {
				return false, fmt.Errorf("claim '%s' value '%v' doesn't match expected '%v'", key, current, ev)
			}
		case []string:
			// For []string, check if any of the values match (OR condition)
			if cv, ok := current.(string); ok {
				found := false
				for _, v := range ev {
					if cv == v {
						found = true
						break
					}
				}
				if !found {
					return false, fmt.Errorf("claim '%s' value '%v' doesn't match any of expected values %v", key, current, ev)
				}
			} else if cvSlice, ok := current.([]interface{}); ok {
				// Handle case where claim is an array
				found := false
				for _, claimVal := range cvSlice {
					if claimStr, ok := claimVal.(string); ok {
						for _, expectedVal := range ev {
							if claimStr == expectedVal {
								found = true
								break
							}
						}
						if found {
							break
						}
					}
				}
				if !found {
					return false, fmt.Errorf("claim '%s' array doesn't contain any of expected values %v", key, ev)
				}
			} else {
				return false, fmt.Errorf("claim '%s' is not a string or string array value", key)
			}
		case []interface{}:
			// Handle []interface{} for more flexible array matching
			switch cv := current.(type) {
			case string:
				found := false
				for _, v := range ev {
					if vStr, ok := v.(string); ok && cv == vStr {
						found = true
						break
					}
				}
				if !found {
					return false, fmt.Errorf("claim '%s' value '%v' doesn't match any of expected values %v", key, current, ev)
				}
			case []interface{}:
				found := false
				for _, claimVal := range cv {
					for _, expectedVal := range ev {
						if claimVal == expectedVal {
							found = true
							break
						}
					}
					if found {
						break
					}
				}
				if !found {
					return false, fmt.Errorf("claim '%s' array doesn't contain any of expected values %v", key, ev)
				}
			default:
				return false, fmt.Errorf("claim '%s' type doesn't match expected array type", key)
			}
		case float64:
			// Handle numeric claims
			if cv, ok := current.(float64); !ok || cv != ev {
				return false, fmt.Errorf("claim '%s' value '%v' doesn't match expected '%v'", key, current, ev)
			}
		case bool:
			// Handle boolean claims
			if cv, ok := current.(bool); !ok || cv != ev {
				return false, fmt.Errorf("claim '%s' value '%v' doesn't match expected '%v'", key, current, ev)
			}
		default:
			// Generic comparison for other types
			if current != expectedValue {
				return false, fmt.Errorf("claim '%s' value '%v' doesn't match expected '%v'", key, current, expectedValue)
			}
		}
	}

	return true, nil
}

// Helper function to validate standard JWT claims if needed
func (jwtAuth JwtAuth) validateStandardClaims(claims jwt.MapClaims) error {
	// Validate issuer if specified
	if jwtAuth.Issuer != "" {
		if iss, ok := claims["iss"].(string); !ok || iss != jwtAuth.Issuer {
			return fmt.Errorf("invalid issuer")
		}
	}

	// Validate audience if specified
	if jwtAuth.Audience != "" {
		if aud, ok := claims["aud"].(string); ok {
			if aud != jwtAuth.Audience {
				return fmt.Errorf("invalid audience")
			}
		} else if audSlice, ok := claims["aud"].([]interface{}); ok {
			found := false
			for _, a := range audSlice {
				if audStr, ok := a.(string); ok && audStr == jwtAuth.Audience {
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("invalid audience")
			}
		} else {
			return fmt.Errorf("audience claim missing or invalid")
		}
	}

	return nil
}

// forwardHeadersFromClaims extracts values from JWT claims and sets them as HTTP headers
func (jwtAuth JwtAuth) forwardHeadersFromClaims(token *jwt.Token, headers map[string][]string) error {
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
func (jwtAuth JwtAuth) extractNestedClaimValue(claims jwt.MapClaims, claimKey string) (interface{}, error) {
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
func (jwtAuth JwtAuth) formatHeaderValue(claimValue interface{}) string {
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
