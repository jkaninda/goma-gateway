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

// Middleware redirects requests to the specified scheme (e.g., HTTP to HTTPS).
// ACME challenge requests are always allowed through without redirection.
func (rs *RedirectScheme) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !rs.shouldRedirect(r) {
			next.ServeHTTP(w, r)
			return
		}

		targetURL := rs.buildRedirectURL(r)
		http.Redirect(w, r, targetURL, rs.redirectStatusCode())
	})
}

// shouldRedirect determines if the request should be redirected based on scheme
// and whether it's an ACME challenge request
func (rs *RedirectScheme) shouldRedirect(r *http.Request) bool {
	if scheme(r) == rs.Scheme || rs.isACMEChallenge(r) {
		return false
	}
	return true
}

// isACMEChallenge checks if the request is for an ACME challenge
func (rs *RedirectScheme) isACMEChallenge(r *http.Request) bool {
	return strings.HasPrefix(r.URL.Path, "/.well-known/acme-challenge/")
}

// redirectStatusCode returns the appropriate HTTP status code for redirection
func (rs *RedirectScheme) redirectStatusCode() int {
	if rs.Permanent {
		return http.StatusMovedPermanently
	}
	return http.StatusFound
}

func (rs *RedirectScheme) buildRedirectURL(r *http.Request) string {
	host := r.Host
	if rs.Port >= 0 {
		host = strings.Split(host, ":")[0]
		host = fmt.Sprintf("%s:%d", host, rs.Port)
	}

	url := fmt.Sprintf("%s://%s%s", rs.Scheme, host, r.URL.Path)
	if r.URL.RawQuery != "" {
		url += "?" + r.URL.RawQuery
	}
	return url
}
