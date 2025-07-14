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
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/time/rate"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// AuthMiddleware checks for the Authorization header and verifies the credentials
func (basicAuth *AuthBasic) AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isPathMatching(r.URL.Path, basicAuth.Path, basicAuth.Paths) {
			next.ServeHTTP(w, r)
			return
		}

		contentType := r.Header.Get("Content-Type")
		if basicAuth.Realm == "" {
			basicAuth.Realm = "Restricted"
		}

		authHeader := r.Header.Get("Authorization")
		if authHeader == "" || !strings.HasPrefix(authHeader, "Basic ") {
			logger.Debug("Missing or invalid Authorization header")
			unauthorizedResponse(w, r, basicAuth.Realm, contentType)
			return
		}

		payload, err := base64.StdEncoding.DecodeString(authHeader[len("Basic "):])
		if err != nil {
			logger.Debug("Failed to decode base64 auth payload")
			unauthorizedResponse(w, r, basicAuth.Realm, contentType)
			return
		}

		parts := strings.SplitN(string(payload), ":", 2)
		if len(parts) != 2 {
			logger.Debug("Malformed Basic auth credentials")
			unauthorizedResponse(w, r, basicAuth.Realm, contentType)
			return
		}

		// Rate limiting for LDAP authentication
		if basicAuth.Ldap != nil {
			basicAuth.rateLimitInit.Do(basicAuth.initRateLimit)

			// Check rate limit before attempting LDAP authentication
			if !basicAuth.checkRateLimit() {
				logger.Warn("Too many requests", "ip", getRealIP(r), "url", r.URL, "user_agent", r.UserAgent())
				tooManyRequestsResponse(w, r, basicAuth.rateLimitTTL, basicAuth.Realm, contentType)
				return
			}
		}

		if !basicAuth.validateCredentials(parts[0], parts[1]) {
			logger.Warn("Invalid credentials", "auth", "basicAuth", "username", parts[0], "ip", getRealIP(r))
			unauthorizedResponse(w, r, basicAuth.Realm, contentType)
			return
		}

		if basicAuth.ForwardUsername {
			r.Header.Set("username", parts[0])
		}
		next.ServeHTTP(w, r)
	})
}
func (basicAuth *AuthBasic) initRateLimit() {
	if basicAuth.ConnPoolSize <= 0 {
		basicAuth.ConnPoolSize = 10
	}
	if basicAuth.ConnPoolBurst <= 0 {
		basicAuth.ConnPoolBurst = 20
	}

	// Parse TTL string to duration
	if basicAuth.ConnPoolTTL != "" {
		if ttl, err := time.ParseDuration(basicAuth.ConnPoolTTL); err == nil {
			basicAuth.rateLimitTTL = ttl
		} else {
			basicAuth.rateLimitTTL = time.Minute
		}
	} else {
		basicAuth.rateLimitTTL = time.Minute
	}

	limit := rate.Every(basicAuth.rateLimitTTL / time.Duration(basicAuth.ConnPoolSize))
	basicAuth.rateLimiter = rate.NewLimiter(limit, basicAuth.ConnPoolBurst)
}

// checkRateLimit checks if the request should be rate limited
func (basicAuth *AuthBasic) checkRateLimit() bool {
	basicAuth.rateLimitMu.RLock()
	defer basicAuth.rateLimitMu.RUnlock()

	if basicAuth.rateLimiter == nil {
		return true
	}

	return basicAuth.rateLimiter.Allow()
}

func unauthorizedResponse(w http.ResponseWriter, r *http.Request, realm, contentType string) {
	w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Basic realm="%s"`, realm))
	RespondWithError(w, r, http.StatusUnauthorized, fmt.Sprintf("%d %s", http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized)), nil, contentType)
}
func tooManyRequestsResponse(w http.ResponseWriter, r *http.Request, ttl time.Duration, realm, contentType string) {
	w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Basic realm="%s"`, realm))
	w.Header().Set("Retry-After", strconv.Itoa(int(ttl.Seconds())))
	RespondWithError(w, r, http.StatusTooManyRequests, fmt.Sprintf("%d %s", http.StatusTooManyRequests, http.StatusText(http.StatusTooManyRequests)), nil, contentType)
}

func (basicAuth *AuthBasic) validateCredentials(username, password string) bool {
	if basicAuth.Ldap != nil {
		return basicAuth.Ldap.authenticateLDAP(username, password)
	} else {
		for _, entry := range basicAuth.Users {
			u := strings.SplitN(entry, ":", 2)
			if len(u) != 2 {
				logger.Debug("Skipping invalid user entry", "entry", entry)
				continue
			}
			storedUser, storedHash := u[0], u[1]
			if username == storedUser {
				ok, err := ValidatePassword(password, storedHash)
				if err != nil {
					logger.Error("Password validation error", "err", err)
					return false
				}
				return ok
			}
		}
	}
	return false
}

func ValidatePassword(plain, hash string) (bool, error) {
	switch {
	case strings.HasPrefix(hash, "$2y$"), strings.HasPrefix(hash, "$2a$"):
		return bcrypt.CompareHashAndPassword([]byte(hash), []byte(plain)) == nil, nil
	case strings.HasPrefix(hash, "$apr1$"):
		return validateMD5Crypt(plain, hash)
	case strings.HasPrefix(hash, "{SHA}"):
		return validateSHA1(plain, hash)
	default:
		return validatePlainText(plain, hash)
	}
}

func validatePlainText(plain, hash string) (bool, error) {
	return subtle.ConstantTimeCompare([]byte(plain), []byte(hash)) == 1, nil
}

func validateSHA1(plain, hash string) (bool, error) {
	encoded := hash[len("{SHA}"):]
	expected, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return false, err
	}
	h := sha1.New()
	h.Write([]byte(plain))
	computed := h.Sum(nil)
	return subtle.ConstantTimeCompare(computed, expected) == 1, nil
}

func validateMD5Crypt(plain, hash string) (bool, error) {

	// Check if hash has the correct MD5 crypt format: $1$salt$hash
	if !strings.HasPrefix(hash, "$1$") {
		return false, fmt.Errorf("invalid MD5 crypt format: must start with $1$")
	}

	// Split the hash to extract salt and hash parts
	parts := strings.Split(hash, "$")
	if len(parts) != 4 || parts[0] != "" || parts[1] != "1" {
		return false, fmt.Errorf("invalid MD5 crypt format: expected $1$salt$hash")
	}

	salt := parts[2]

	// Generate the hash using the same salt
	generatedHash := generateMD5Crypt(plain, salt)

	// Compare the generated hash with the expected hash
	return generatedHash == hash, nil
}
