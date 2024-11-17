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
	"encoding/base64"
	"github.com/jkaninda/goma-gateway/pkg/logger"
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
		for _, header := range jwtAuth.RequiredHeaders {
			if r.Header.Get(header) == "" {
				logger.Error("Proxy error, missing %s header", header)
				w.Header().Set("Content-Type", "application/json")
				// check allowed origin
				if allowedOrigin(jwtAuth.Origins, r.Header.Get("Origin")) {
					w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
				}
				RespondWithError(w, http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized))
				return

			}
		}
		authURL, err := url.Parse(jwtAuth.AuthURL)
		if err != nil {
			logger.Error("Error parsing auth URL: %v", err)
			RespondWithError(w, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError))
			return
		}
		// Create a new request for /authentication
		authReq, err := http.NewRequest("GET", authURL.String(), nil)
		if err != nil {
			logger.Error("Proxy error creating authentication request: %v", err)
			RespondWithError(w, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError))
			return
		}
		logger.Trace("JWT Auth response headers: %v", authReq.Header)
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
			RespondWithError(w, http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized))
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

		next.ServeHTTP(w, r)
	})
}

// AuthMiddleware checks for the Authorization header and verifies the credentials
func (basicAuth AuthBasic) AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger.Trace("Basic-Auth request headers: %v", r.Header)
		// Get the Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			logger.Debug("Proxy error, missing Authorization header")
			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
			RespondWithError(w, http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized))
			return
		}
		// Check if the Authorization header contains "Basic" scheme
		if !strings.HasPrefix(authHeader, "Basic ") {
			logger.Error("Proxy error, missing Basic Authorization header")
			RespondWithError(w, http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized))

			return
		}

		// Decode the base64 encoded username:password string
		payload, err := base64.StdEncoding.DecodeString(authHeader[len("Basic "):])
		if err != nil {
			logger.Debug("Proxy error, missing Basic Authorization header")
			RespondWithError(w, http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized))
			return
		}

		// Split the payload into username and password
		pair := strings.SplitN(string(payload), ":", 2)
		if len(pair) != 2 || pair[0] != basicAuth.Username || pair[1] != basicAuth.Password {
			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
			RespondWithError(w, http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized))
			return
		}

		// Continue to the next handler if the authentication is successful
		next.ServeHTTP(w, r)
	})

}
