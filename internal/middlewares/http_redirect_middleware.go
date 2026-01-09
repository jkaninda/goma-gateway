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
	"net/url"
	"regexp"
	"strings"
)

// RedirectScheme middleware configuration for scheme-based redirects (HTTP to HTTPS)
type RedirectScheme struct {
	Scheme    string
	Port      int64 // Optional custom port
	Permanent bool  // Use 301 instead of 302
}

// Redirect middleware configuration for URL-based redirects
type Redirect struct {
	URL       string // Target URL (absolute or relative)
	Permanent bool   // Use 301 instead of 302
}

// RedirectRegex middleware configuration for regex-based redirects
type RedirectRegex struct {
	Pattern     string `yaml:"pattern"`
	Replacement string `yaml:"replacement"`
	Permanent   bool   `yaml:"permanent,omitempty"`
	regex       *regexp.Regexp
}

// Middleware redirects requests to the specified scheme (e.g., HTTP to HTTPS).
// ACME challenge requests are always allowed through without redirection.
func (rs *RedirectScheme) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Validate configuration on first use
		if rs.Scheme == "" {
			http.Error(w, "RedirectScheme: scheme not configured", http.StatusInternalServerError)
			return
		}

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
	if scheme(r) == rs.Scheme {
		return false
	}
	if rs.isACMEChallenge(r) {
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
		return http.StatusMovedPermanently // 301
	}
	return http.StatusFound // 302
}

// buildRedirectURL constructs the target URL with the new scheme
func (rs *RedirectScheme) buildRedirectURL(r *http.Request) string {
	host := r.Host

	// Handle custom port
	if rs.Port != 0 {
		// Remove existing port if present
		if colonIndex := strings.LastIndex(host, ":"); colonIndex != -1 {
			// Check if it's actually a port
			if !strings.Contains(host[colonIndex:], "]") {
				host = host[:colonIndex]
			}
		}

		// Only add port if it's not the default for the scheme
		if !rs.isDefaultPort(rs.Scheme, rs.Port) {
			host = fmt.Sprintf("%s:%d", host, rs.Port)
		}
	}

	// Build the full URL
	rUrl := fmt.Sprintf("%s://%s%s", rs.Scheme, host, r.URL.Path)
	if r.URL.RawQuery != "" {
		rUrl += "?" + r.URL.RawQuery
	}
	if r.URL.Fragment != "" {
		rUrl += "#" + r.URL.Fragment
	}

	return rUrl
}

// isDefaultPort checks if the port is the default for the scheme
func (rs *RedirectScheme) isDefaultPort(scheme string, port int64) bool {
	return (scheme == "http" && port == 80) || (scheme == "https" && port == 443)
}

// Middleware performs URL-based redirects
func (rd *Redirect) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Validate configuration
		if rd.URL == "" {
			http.Error(w, "Redirect: target URL not configured", http.StatusInternalServerError)
			return
		}
		if rd.isACMEChallenge(r) {
			next.ServeHTTP(w, r)
			return
		}

		targetURL := rd.buildRedirectURL(r)
		http.Redirect(w, r, targetURL, rd.redirectStatusCode())
	})
}

// isACMEChallenge checks if the request is for an ACME challenge
func (rd *Redirect) isACMEChallenge(r *http.Request) bool {
	return strings.HasPrefix(r.URL.Path, "/.well-known/acme-challenge/")
}

// redirectStatusCode returns the appropriate HTTP status code for redirection
func (rd *Redirect) redirectStatusCode() int {
	if rd.Permanent {
		return http.StatusMovedPermanently // 301
	}
	return http.StatusFound // 302
}

// buildRedirectURL constructs the target URL, preserving query parameters if needed
func (rd *Redirect) buildRedirectURL(r *http.Request) string {
	targetURL := rd.URL

	// Parse the target URL to check if it's absolute or relative
	parsedTarget, err := url.Parse(targetURL)
	if err != nil {
		return targetURL
	}

	// If target URL is relative, preserve the original query and fragment
	if !parsedTarget.IsAbs() {
		if r.URL.RawQuery != "" && parsedTarget.RawQuery == "" {
			if strings.Contains(targetURL, "?") {
				targetURL += "&" + r.URL.RawQuery
			} else {
				targetURL += "?" + r.URL.RawQuery
			}
		}
		if r.URL.Fragment != "" && parsedTarget.Fragment == "" {
			targetURL += "#" + r.URL.Fragment
		}
	}

	return targetURL
}

// Middleware performs regex-based URL redirects
func (rr *RedirectRegex) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if rr.regex == nil {
			if err := rr.compilePattern(); err != nil {
				http.Error(w, fmt.Sprintf("RedirectRegex: invalid pattern: %v", err), http.StatusInternalServerError)
				return
			}
		}

		// Validate configuration
		if rr.Pattern == "" {
			http.Error(w, "RedirectRegex: pattern not configured", http.StatusInternalServerError)
			return
		}

		if rr.Replacement == "" {
			http.Error(w, "RedirectRegex: replacement not configured", http.StatusInternalServerError)
			return
		}

		if rr.isACMEChallenge(r) {
			next.ServeHTTP(w, r)
			return
		}

		// Check if the request matches the pattern
		if !rr.matches(r) {
			next.ServeHTTP(w, r)
			return
		}

		targetURL := rr.buildRedirectURL(r)
		http.Redirect(w, r, targetURL, rr.redirectStatusCode())
	})
}

// compilePattern compiles the regex pattern
func (rr *RedirectRegex) compilePattern() error {
	if rr.Pattern == "" {
		return fmt.Errorf("pattern is empty")
	}

	regex, err := regexp.Compile(rr.Pattern)
	if err != nil {
		return fmt.Errorf("failed to compile pattern: %w", err)
	}

	rr.regex = regex
	return nil
}

// matches checks if the request URL matches the regex pattern
func (rr *RedirectRegex) matches(r *http.Request) bool {
	requestURL := r.URL.Path
	if r.URL.RawQuery != "" {
		requestURL += "?" + r.URL.RawQuery
	}

	return rr.regex.MatchString(requestURL)
}

// buildRedirectURL constructs the target URL using regex replacement
func (rr *RedirectRegex) buildRedirectURL(r *http.Request) string {
	// Build the full request URL path
	requestURL := r.URL.Path
	if r.URL.RawQuery != "" {
		requestURL += "?" + r.URL.RawQuery
	}

	targetURL := rr.regex.ReplaceAllString(requestURL, rr.Replacement)

	if !strings.Contains(targetURL, "://") {
		if r.URL.Fragment != "" && !strings.Contains(targetURL, "#") {
			targetURL += "#" + r.URL.Fragment
		}
	}

	return targetURL
}

// isACMEChallenge checks if the request is for an ACME challenge
func (rr *RedirectRegex) isACMEChallenge(r *http.Request) bool {
	return strings.HasPrefix(r.URL.Path, "/.well-known/acme-challenge/")
}

// redirectStatusCode returns the appropriate HTTP status code for redirection
func (rr *RedirectRegex) redirectStatusCode() int {
	if rr.Permanent {
		return http.StatusMovedPermanently // 301
	}
	return http.StatusFound // 302
}

// scheme extracts the scheme from the request
func scheme(r *http.Request) string {
	// Check X-Forwarded-Proto header
	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		return strings.ToLower(proto)
	}

	// Check X-Forwarded-Scheme header
	if rScheme := r.Header.Get("X-Forwarded-Scheme"); rScheme != "" {
		return strings.ToLower(rScheme)
	}

	// Check if TLS is used
	if r.TLS != nil {
		return "https"
	}

	// Default to the URL scheme
	if r.URL.Scheme != "" {
		return strings.ToLower(r.URL.Scheme)
	}

	return "http"
}
