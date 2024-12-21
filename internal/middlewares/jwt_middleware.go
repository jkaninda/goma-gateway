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
	"github.com/jkaninda/goma-gateway/pkg/logger"
	"io"
	"net/http"
	"net/url"
)

// AuthMiddleware authenticates the client using JWT
//
// authorization based on the result of backend's response and continue the request when the client is authorized
func (jwtAuth JwtAuth) AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		contentType := r.Header.Get("Content-Type")
		if isProtectedPath(r.URL.Path, jwtAuth.Path, jwtAuth.Paths) {
			// Validate the required headers
			validateHeaders(r, jwtAuth.RequiredHeaders, jwtAuth.Origins, w, r, contentType)
			// Parse the auth URL
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
			copyHeadersAndCookies(r, authReq)
			// Perform the request to the auth service
			client := &http.Client{}
			authResp, err := client.Do(authReq)
			if err != nil || authResp.StatusCode != http.StatusOK {
				logger.Error("Unauthorized access to %s, proxy authentication resulted with status code: %d ", r.URL.Path, authResp.StatusCode)
				RespondWithError(w, r, http.StatusUnauthorized, fmt.Sprintf("%d %s", http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized)), jwtAuth.Origins, contentType)
				return
			}
			// Close the response body
			defer func(Body io.ReadCloser) {
				err := Body.Close()
				if err != nil {
					logger.Error("Error closing body: %v", err)
				}
			}(authResp.Body)
			// Inject specific header to the current request's header
			// Inject header to the next request from AuthRequest header, depending on requirements
			if jwtAuth.Headers != nil {
				for k, v := range jwtAuth.Headers {
					r.Header.Set(v, authResp.Header.Get(k))
				}
			}
			query := r.URL.Query()
			// Add query parameters to the next request from AuthRequest header, depending on requirements
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

// validateHeaders checks if the required headers are present in the request
func validateHeaders(r *http.Request, requiredHeaders []string, origins []string, w http.ResponseWriter, req *http.Request, contentType string) bool {
	for _, header := range requiredHeaders {
		if r.Header.Get(header) == "" {
			logger.Error("Proxy error, missing %s header", header)
			if allowedOrigin(origins, r.Header.Get("Origin")) {
				w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
			}
			RespondWithError(w, req, http.StatusUnauthorized, fmt.Sprintf("%d %s", http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized)), origins, contentType)
			return false
		}
	}
	return true
}

// copyHeadersAndCookies copies headers and cookies from the source request to the destination request
func copyHeadersAndCookies(src *http.Request, dest *http.Request) {
	for name, values := range src.Header {
		for _, value := range values {
			dest.Header.Set(name, value)
		}
	}
	for _, cookie := range src.Cookies() {
		dest.AddCookie(cookie)
	}
}
