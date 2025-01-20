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
	"fmt"
	"net/http"
	"strings"
)

type RedirectScheme struct {
	Scheme    string
	Port      int64
	Permanent bool
}

// Middleware is a middleware that redirects HTTP scheme.
func (h RedirectScheme) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if getScheme(r) != h.Scheme {
			httpsURL := fmt.Sprintf("%s://%s%s", h.Scheme, r.Host, r.URL.Path)
			if h.Port >= 0 {
				host := strings.Split(r.Host, ":")[0]
				httpsURL = fmt.Sprintf("%s://%s:%d%s", h.Scheme, host, h.Port, r.URL.Path)

			}
			if r.URL.RawQuery != "" {
				httpsURL += "?" + r.URL.RawQuery
			}
			// Redirect URL
			if h.Permanent {
				http.Redirect(w, r, httpsURL, http.StatusMovedPermanently)
				return
			}
			http.Redirect(w, r, httpsURL, http.StatusFound)
			return
		}

		next.ServeHTTP(w, r)
	})
}
func getScheme(r *http.Request) string {
	// Check if the request is behind a reverse proxy
	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		return strings.ToLower(proto)
	}

	// Check if the request is using TLS
	if r.TLS != nil {
		return "https"
	}

	// Default to HTTP
	return "http"
}
