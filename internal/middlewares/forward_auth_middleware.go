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
	"crypto/tls"
	"fmt"
	"github.com/jkaninda/goma-gateway/pkg/logger"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// AuthMiddleware authenticates the client using JWT
//
// authorization based on the result of backend's response and continue the request when the client is authorized
func (jwtAuth ForwardAuth) AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		contentType := r.Header.Get("Content-Type")
		if isProtectedPath(r.URL.Path, jwtAuth.Path, jwtAuth.Paths) {
			// Authenticate the request
			authenticated, authResponse := authRequest(jwtAuth, r, w, r, contentType)
			if !authenticated {
				return
			}
			// Inject headers and parameters
			authInjectHeadersAndParams(jwtAuth, r, authResponse)

		}
		next.ServeHTTP(w, r)
	})
}

// authRequest authenticates the request using the authURL
func authRequest(f ForwardAuth, r *http.Request, w http.ResponseWriter, req *http.Request, contentType string) (bool, *http.Response) {
	parsedURL, err := url.Parse(f.AuthURL)
	if err != nil {
		logger.Error("Error parsing auth URL: %v", err)
		RespondWithError(w, req, http.StatusInternalServerError, fmt.Sprintf("%d %s", http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError)), f.Origins, contentType)
		return false, &http.Response{StatusCode: http.StatusInternalServerError}
	}
	authReq, err := http.NewRequest("GET", parsedURL.String(), nil)
	if err != nil {
		logger.Error("Proxy error creating authentication request: %v", err)
		RespondWithError(w, req, http.StatusInternalServerError, fmt.Sprintf("%d %s", http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError)), f.Origins, contentType)
		return false, &http.Response{StatusCode: http.StatusInternalServerError}
	}
	// Copy headers and cookies from the original request to the authentication request
	authCopyHeadersAndCookies(f, r, authReq)
	// Create custom transport with TLS configuration
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // Skip SSL certificate verification
		},
	}
	client := &http.Client{Transport: transport}
	authResp, err := client.Do(authReq)
	if err != nil || authResp.StatusCode != http.StatusOK {
		if err != nil {
			logger.Error("Proxy error authenticating request: %v", err)

		} else {
			logger.Error("Unauthorized access to %s, proxy authentication resulted with status code: %d ", r.URL.Path, authResp.StatusCode)
		}
		RespondWithError(w, req, http.StatusUnauthorized, fmt.Sprintf("%d %s", http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized)), f.Origins, contentType)
		return false, authResp
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			logger.Error("Error closing response body: %v", err)
		}
	}(authResp.Body)
	return true, authResp
}

// copyHeadersAndCookies copies headers and cookies from the source request to the destination request
func authCopyHeadersAndCookies(f ForwardAuth, src *http.Request, dest *http.Request) {
	if f.TrustForwardHeaders {
		dest.Header.Set("X-Forwarded-Host", src.Header.Get("Host"))
		dest.Header.Set("X-Forwarded-For", getRealIP(src))
		dest.Header.Set("X-Real-IP", getRealIP(src))
	}
	if f.AuthRequestHeaders != nil {
		for _, header := range f.AuthRequestHeaders {
			if src.Header.Get(header) != "" {
				dest.Header.Set(header, src.Header.Get(header))
			}
		}
	}
	for _, cookie := range src.Cookies() {
		dest.AddCookie(cookie)
	}

}

// authInjectHeadersAndParams injects headers and parameters from the authentication response into the request.
// It updates the request headers and query parameters based on the provided forwardAuth configuration.
func authInjectHeadersAndParams(f ForwardAuth, r *http.Request, authResp *http.Response) {
	// Inject headers from the authentication response into the current request's headers.
	if len(f.AuthResponseHeaders) != 0 {
		for _, v := range f.AuthResponseHeaders {
			v = strings.ReplaceAll(v, " ", "") // Remove all spaces
			// check if v has colon to split key:value pair
			if strings.Contains(v, ":") {
				pair := strings.SplitN(v, ":", 2)
				if len(pair) != 2 {
					logger.Error("Invalid header key:value pair: %s", v)
					continue
				}
				r.Header.Set(pair[1], authResp.Header.Get(pair[0]))
			} else {
				r.Header.Set(v, authResp.Header.Get(v))
			}

		}
	}
	// Inject query parameters from the authentication response headers into the current request's parameters.
	query := r.URL.Query()
	if len(f.AuthResponseHeadersAsParams) != 0 {
		for _, v := range f.AuthResponseHeadersAsParams {
			v = strings.ReplaceAll(v, " ", "") // Remove all spaces
			// check if v has colon to split key:value pair
			if strings.Contains(v, ":") {
				pair := strings.SplitN(v, ":", 2)
				if len(pair) != 2 {
					logger.Error("Invalid header key:value pair: %s", v)
					continue
				}
				query.Set(pair[1], authResp.Header.Get(pair[0]))
			} else {
				query.Set(v, authResp.Header.Get(v))
			}
		}
	}
	r.URL.RawQuery = query.Encode()
}
