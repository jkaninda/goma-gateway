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
		// The gateway owns this header. It is only Set on a guarded path and
		// only when forwardUsername is on, so without this a client could
		// supply its own and have the upstream trust it.
		r.Header.Del("username")

		if !isGuardedPathMatching(r.URL.Path, basicAuth.Path, basicAuth.Paths) {
			next.ServeHTTP(w, r)
			return
		}

		contentType := getContentType(r)
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
		if len(parts[0]) == 0 || len(parts[1]) == 0 {
			logger.Debug("Malformed Basic auth credentials")
			unauthorizedResponse(w, r, basicAuth.Realm, contentType)
			return
		}

		// Rate limiting for LDAP authentication
		if basicAuth.Ldap != nil {
			basicAuth.rateLimitInit.Do(basicAuth.initRateLimit)

			// Check rate limit before attempting LDAP authentication
			if !basicAuth.checkRateLimit() {
				logger.Warn("Too many requests", "ip", RealIP(r), "url", r.URL, "user_agent", r.UserAgent())
				tooManyRequestsResponse(w, r, basicAuth.rateLimitTTL, basicAuth.Realm, contentType)
				return
			}
		}

		if !basicAuth.validateCredentials(parts[0], parts[1]) {
			logger.Warn("Invalid credentials", "auth", "basicAuth", "username", parts[0], "ip", RealIP(r))
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
	}

	for _, user := range basicAuth.Users {
		if subtle.ConstantTimeCompare([]byte(username), []byte(user.Username)) == 1 {
			ok, err := ValidatePassword(password, user.Password)
			if err != nil {
				logger.Error("Password validation error", "err", err)
				return false
			}
			return ok
		}
	}

	// Verify against a decoy so an unknown username costs what a known one
	// costs. Returning early would let a caller tell the two apart by timing
	// and enumerate the user list.
	if _, err := ValidatePassword(password, decoyPasswordHash); err != nil {
		logger.Debug("Decoy password validation failed", "err", err)
	}
	return false
}

// decoyPasswordHash exists only so an unknown username performs the same work
// as a known one. Its plaintext is unused; the comparison is what matters, and
// its result is discarded.
const decoyPasswordHash = "$2a$10$cuP9xB2TreX18wJ0JYFV8OZTcSx6oKukzmwR6UYaO068wA2NNzEM6"

func ValidatePassword(plain, hash string) (bool, error) {
	switch {
	// Every bcrypt revision, not just the two Go's own generator emits.
	// "$2b$" (Python bcrypt, bcryptjs) and "$2x$" used to fall through to the
	// plaintext branch, which made the hash string itself a working password
	// for anyone who could read the config file.
	case strings.HasPrefix(hash, "$2y$"), strings.HasPrefix(hash, "$2a$"),
		strings.HasPrefix(hash, "$2b$"), strings.HasPrefix(hash, "$2x$"):
		return bcrypt.CompareHashAndPassword([]byte(hash), []byte(plain)) == nil, nil
	case strings.HasPrefix(hash, "$apr1$"):
		return validateAPR1(plain, hash)
	case strings.HasPrefix(hash, "$1$"):
		return validateMD5Crypt(plain, hash)
	case strings.HasPrefix(hash, "{SHA}"):
		return validateSHA1(plain, hash)
	default:
		// A value shaped like a hash but in an unsupported scheme must never be
		// compared as a literal password. Genuine plaintext entries — which the
		// configuration format still allows — do not start with these markers.
		if strings.HasPrefix(hash, "$") || strings.HasPrefix(hash, "{") {
			return false, fmt.Errorf("unsupported password hash scheme")
		}
		return validatePlainText(plain, hash)
	}
}

// validateAPR1 verifies an Apache htpasswd "$apr1$" hash: MD5 crypt with the
// "$apr1$" magic. These used to be routed at validateMD5Crypt, which rejects
// anything not starting with "$1$", so an apr1 user could never authenticate.
func validateAPR1(plain, hash string) (bool, error) {
	parts := strings.Split(hash, "$")
	if len(parts) != 4 || parts[0] != "" || parts[1] != "apr1" {
		return false, fmt.Errorf("invalid apr1 format: expected $apr1$salt$hash")
	}
	generated := generateMD5CryptWithMagic(plain, parts[2], "$apr1$")
	return subtle.ConstantTimeCompare([]byte(generated), []byte(hash)) == 1, nil
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
	return subtle.ConstantTimeCompare([]byte(generatedHash), []byte(hash)) == 1, nil
}
