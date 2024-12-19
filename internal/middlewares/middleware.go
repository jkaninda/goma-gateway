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
			if !validateHeaders(r, jwtAuth.RequiredHeaders, jwtAuth.Origins, w, r, contentType) {
				return
			}
			if !authenticateRequest(jwtAuth.AuthURL, r, w, r, jwtAuth.Origins, contentType) {
				return
			}
			injectHeadersAndParams(r, jwtAuth.Headers, jwtAuth.Params)
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

// authenticateRequest authenticates the request using the authURL
func authenticateRequest(authURL string, r *http.Request, w http.ResponseWriter, req *http.Request, origins []string, contentType string) bool {
	parsedURL, err := url.Parse(authURL)
	if err != nil {
		logger.Error("Error parsing auth URL: %v", err)
		RespondWithError(w, req, http.StatusInternalServerError, fmt.Sprintf("%d %s", http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError)), origins, contentType)
		return false
	}
	authReq, err := http.NewRequest("GET", parsedURL.String(), nil)
	if err != nil {
		logger.Error("Proxy error creating authentication request: %v", err)
		RespondWithError(w, req, http.StatusInternalServerError, fmt.Sprintf("%d %s", http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError)), origins, contentType)
		return false
	}
	copyHeadersAndCookies(r, authReq)
	client := &http.Client{}
	authResp, err := client.Do(authReq)
	if err != nil || authResp.StatusCode != http.StatusOK {
		logger.Debug("%s %s %s %s", r.Method, getRealIP(r), r.URL, r.UserAgent())
		logger.Debug("Proxy authentication error")
		RespondWithError(w, req, http.StatusUnauthorized, fmt.Sprintf("%d %s", http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized)), origins, contentType)
		return false
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			logger.Error("Error closing response body: %v", err)
		}
	}(authResp.Body)
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

// injectHeadersAndParams injects headers and parameters into the request
func injectHeadersAndParams(r *http.Request, headers map[string]string, params map[string]string) {
	for k, v := range headers {
		r.Header.Set(v, r.Header.Get(k))
	}
	if params != nil {
		query := r.URL.Query()
		for k, v := range params {
			query.Set(v, r.Header.Get(k))
		}
		r.URL.RawQuery = query.Encode()
	}
}
