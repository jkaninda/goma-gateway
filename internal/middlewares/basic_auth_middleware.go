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
	"net/http"
	"strings"
)

// AuthMiddleware checks for the Authorization header and verifies the credentials
func (basicAuth AuthBasic) AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isPathMatching(r.URL.Path, basicAuth.Path, basicAuth.Paths) {
			next.ServeHTTP(w, r)
			return
		}

		contentType := r.Header.Get("Content-Type")
		realm := basicAuth.Realm
		if realm == "" {
			realm = "Restricted"
		}

		authHeader := r.Header.Get("Authorization")
		if authHeader == "" || !strings.HasPrefix(authHeader, "Basic ") {
			logger.Debug("Missing or invalid Authorization header")
			unauthorizedResponse(w, r, realm, contentType)
			return
		}

		payload, err := base64.StdEncoding.DecodeString(authHeader[len("Basic "):])
		if err != nil {
			logger.Debug("Failed to decode base64 auth payload")
			unauthorizedResponse(w, r, realm, contentType)
			return
		}

		parts := strings.SplitN(string(payload), ":", 2)
		if len(parts) != 2 {
			logger.Debug("Malformed Basic auth credentials")
			unauthorizedResponse(w, r, realm, contentType)
			return
		}

		if len(basicAuth.Users) > 0 {
			if !validateCredentials(parts[0], parts[1], basicAuth.Users) {
				logger.Debug("Invalid credentials", "auth", "basicAuth", "username", parts[0])
				unauthorizedResponse(w, r, realm, contentType)
				return
			}
		} else {
			if parts[0] != basicAuth.Username || parts[1] != basicAuth.Password {
				unauthorizedResponse(w, r, realm, contentType)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func unauthorizedResponse(w http.ResponseWriter, r *http.Request, realm, contentType string) {
	w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Basic realm="%s"`, realm))
	RespondWithError(w, r, http.StatusUnauthorized, fmt.Sprintf("%d %s", http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized)), nil, contentType)
}

func validateCredentials(username, password string, users []string) bool {
	for _, entry := range users {
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
