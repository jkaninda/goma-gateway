package middlewares

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
import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/jkaninda/goma-gateway/pkg/logger"
	"golang.org/x/crypto/bcrypt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// AuthMiddleware authenticate the client using JWT
//
//	authorization based on the result of backend's response and continue the request when the client is authorized
func (jwtAuth JwtAuth) AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		contentType := r.Header.Get("Content-Type")
		if isProtectedPath(r.URL.Path, jwtAuth.Path, jwtAuth.Paths) {
			for _, header := range jwtAuth.RequiredHeaders {
				if r.Header.Get(header) == "" {
					logger.Error("Proxy error, missing %s header", header)
					// check allowed origin
					if allowedOrigin(jwtAuth.Origins, r.Header.Get("Origin")) {
						w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
					}
					RespondWithError(w, r, http.StatusUnauthorized, fmt.Sprintf("%d %s", http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized)), jwtAuth.Origins, contentType)
					return

				}
			}
			authURL, err := url.Parse(jwtAuth.AuthURL)
			if err != nil {
				logger.Error("Error parsing auth URL: %v", err)
				RespondWithError(w, r, http.StatusInternalServerError, fmt.Sprintf("%d %s", http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError)), jwtAuth.Origins, contentType)
				return
			}
			// Create a new request for /authentication
			authReq, err := http.NewRequest("GET", authURL.String(), nil)
			if err != nil {
				logger.Error("Proxy error creating authentication request: %v", err)
				RespondWithError(w, r, http.StatusInternalServerError, fmt.Sprintf("%d %s", http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError)), jwtAuth.Origins, contentType)
				return
			}
			// Copy headers from the original request to the new request
			for name, values := range r.Header {
				for _, value := range values {
					authReq.Header.Set(name, value)
				}
			}
			// Copy cookies from the original request to the new request
			for _, cookie := range r.Cookies() {
				authReq.AddCookie(cookie)
			}
			// Perform the request to the auth service
			client := &http.Client{}
			authResp, err := client.Do(authReq)
			if err != nil || authResp.StatusCode != http.StatusOK {
				logger.Debug("%s %s %s %s", r.Method, getRealIP(r), r.URL, r.UserAgent())
				logger.Debug("Proxy authentication error")
				RespondWithError(w, r, http.StatusUnauthorized, fmt.Sprintf("%d %s", http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized)), jwtAuth.Origins, contentType)
				return
			}
			defer func(Body io.ReadCloser) {
				err := Body.Close()
				if err != nil {
					logger.Error("Error closing body: %v", err)
				}
			}(authResp.Body)
			// Inject specific header tp the current request's header
			// Add header to the next request from AuthRequest header, depending on your requirements
			if jwtAuth.Headers != nil {
				for k, v := range jwtAuth.Headers {
					r.Header.Set(v, authResp.Header.Get(k))
				}
			}
			query := r.URL.Query()
			// Add query parameters to the next request from AuthRequest header, depending on your requirements
			if jwtAuth.Params != nil {
				for k, v := range jwtAuth.Params {
					query.Set(v, authResp.Header.Get(k))
				}
			}
			r.URL.RawQuery = query.Encode()
		}
		next.ServeHTTP(w, r)
	})

}

// AuthMiddleware checks for the Authorization header and verifies the credentials
func (basicAuth AuthBasic) AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		contentType := r.Header.Get("Content-Type")
		realm := basicAuth.Realm
		if realm == "" {
			realm = "Restricted"
		}
		if isProtectedPath(r.URL.Path, basicAuth.Path, basicAuth.Paths) {
			// Get the Authorization header
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				logger.Debug("Proxy error, missing Authorization header")
				w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
				RespondWithError(w, r, http.StatusUnauthorized, fmt.Sprintf("%d %s", http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized)), nil, contentType)
				return
			}
			// Check if the Authorization header contains "Basic" scheme
			if !strings.HasPrefix(authHeader, "Basic ") {
				logger.Error("Proxy error, missing Basic Authorization header")
				RespondWithError(w, r, http.StatusUnauthorized, fmt.Sprintf("%d %s", http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized)), nil, contentType)

				return
			}
			// Decode the base64 encoded username:password string
			payload, err := base64.StdEncoding.DecodeString(authHeader[len("Basic "):])
			if err != nil {
				logger.Error("Proxy error, missing Basic Authorization header")
				RespondWithError(w, r, http.StatusUnauthorized, fmt.Sprintf("%d %s", http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized)), nil, contentType)
				return
			}
			// Split the payload into username and password
			pair := strings.SplitN(string(payload), ":", 2)
			if len(pair) != 2 {
				logger.Error("Proxy error, missing Basic Authorization header")
				RespondWithError(w, r, http.StatusUnauthorized, fmt.Sprintf("%d %s", http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized)), nil, contentType)
				return
			}

			if len(basicAuth.Users) > 0 {
				// Decode the credentials
				if !validateCredentials(pair, basicAuth.Users) {
					logger.Error("Error, wrong credentials")
					w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Basic realm="%s"`, realm))
					RespondWithError(w, r, http.StatusUnauthorized, fmt.Sprintf("%d %s", http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized)), nil, contentType)
					return
				}

			} else {
				if pair[0] != basicAuth.Username || pair[1] != basicAuth.Password {
					w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Basic realm="%s"`, realm))
					RespondWithError(w, r, http.StatusUnauthorized, fmt.Sprintf("%d %s", http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized)), nil, contentType)
					return
				}
			}

		}

		// Continue to the next handler if the authentication is successful
		next.ServeHTTP(w, r)
	})

}

// Validate the credentials against the user list
func validateCredentials(parts []string, users []string) bool {
	logger.Debug("Validating credentials")
	username := parts[0]
	password := parts[1]
	for index, user := range users {
		u := strings.SplitN(user, ":", 2)
		if len(parts) != 2 {
			logger.Info("User %s is invalid", user)
			return false
		}
		ok, err := ValidatePassword(password, u[1])
		if err != nil {
			logger.Error("Error validating password: %v", err)
			if len(users) == index {
				return false

			}
			continue
		}
		if u[0] == username && ok {
			return true
		}
	}

	return false
}

// ValidatePassword validates a plaintext password against an htpasswd hash
func ValidatePassword(plainPassword, hashedPassword string) (bool, error) {
	switch {
	case strings.HasPrefix(hashedPassword, "$2y$") || strings.HasPrefix(hashedPassword, "$2a$"):
		// BCrypt
		return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(plainPassword)) == nil, nil

	case strings.HasPrefix(hashedPassword, "$apr1$"):
		// MD5 (Apache-specific format)
		return validateMD5Crypt(plainPassword, hashedPassword)

	case strings.HasPrefix(hashedPassword, "{SHA}"):
		// SHA1
		return validateSHA1(plainPassword, hashedPassword)

	default:
		// Unsupported or plaintext
		return validatePlainText(plainPassword, hashedPassword)
	}
}

// Validate PlainText
func validatePlainText(plainPassword, password string) (bool, error) {
	return subtle.ConstantTimeCompare([]byte(plainPassword), []byte(password)) == 1, nil
}

// Validate MD5 (Apache MD5Crypt format)
func validateMD5Crypt(plainPassword, hashedPassword string) (bool, error) {
	// MD5 hash (Apache variant)
	if md5Hash, err := generateMD5Hash(plainPassword, hashedPassword); err == nil {
		return md5Hash == hashedPassword, nil
	} else {
		return false, err
	}
}

// Validate SHA1 (Base64-encoded SHA1)
func validateSHA1(plainPassword, hashedPassword string) (bool, error) {
	// Decode the base64 hash (strip the "{SHA}" prefix)
	encodedHash := hashedPassword[5:] // Remove "{SHA}"
	expectedHash, err := base64.StdEncoding.DecodeString(encodedHash)
	if err != nil {
		return false, err
	}

	// Compute the SHA1 hash of the plaintext password
	hashes := sha1.New()
	hashes.Write([]byte(plainPassword))
	computedHash := hashes.Sum(nil)

	// Compare hashes
	return subtle.ConstantTimeCompare(computedHash, expectedHash) == 1, nil
}

// generateMD5Hash generates an MD5 hash for the given password and salt
func generateMD5Hash(password, hash string) (string, error) {
	parts := strings.Split(hash, "$")
	if len(parts) != 4 {
		return "", errors.New("invalid MD5 hash format")
	}
	salt := parts[2]

	h := md5.New()
	h.Write([]byte(password + salt))
	md5Hash := "$apr1$" + salt + "$" + base64.StdEncoding.EncodeToString(h.Sum(nil))
	return md5Hash, nil
}
