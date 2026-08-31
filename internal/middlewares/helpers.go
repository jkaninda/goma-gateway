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
	"encoding/json"
	"fmt"
	"html"
	"net"
	"net/http"
	"os"
	"regexp"
	"slices"
	"strings"
	"sync"

	"github.com/jkaninda/goma-gateway/util"
)

var htmlCache = make(map[string][]byte)
var htmlCacheMu sync.RWMutex

// RealIP extracts the real IP address of the client from the HTTP request.
//
// Forwarded-for headers are only read when the request actually arrived from a
// configured trusted proxy: they are client-supplied data, and a gateway that
// believes them from anyone lets every caller choose the IP that access
// policies, geo blocking and rate limits are applied to.
func RealIP(r *http.Request) string {
	remoteIP := socketIP(r)

	if !FromTrustedProxy(r) {
		return remoteIP
	}

	for _, header := range TrustedProxyConfig.IPHeaders {
		if ip := rightmostUntrusted(r.Header.Values(header)); ip != "" {
			return ip
		}
	}
	return remoteIP
}

// socketIP is the address the connection actually came from, which is the only
// value no client can choose.
func socketIP(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil && host != "" {
		return host
	}
	return r.RemoteAddr
}

// FromTrustedProxy reports whether the request arrived from a proxy the
// operator has vouched for, which is the condition for believing any of the
// forwarded-* headers it carries.
func FromTrustedProxy(r *http.Request) bool {
	if TrustedProxyConfig == nil || !TrustedProxyConfig.Enabled {
		return false
	}
	return TrustedProxyConfig.IsTrustedSource(socketIP(r))
}

// rightmostUntrusted walks a forwarded-for chain from the right — the end the
// nearest proxy appended — and returns the first address that is not one of our
// own proxies. Reading from the left would return whatever the original client
// chose to put there, which is exactly the value an attacker controls.
func rightmostUntrusted(values []string) string {
	var chain []string
	for _, value := range values {
		for _, entry := range strings.Split(value, ",") {
			if trimmed := strings.TrimSpace(entry); trimmed != "" {
				chain = append(chain, normalizeIP(trimmed))
			}
		}
	}

	for index := len(chain) - 1; index >= 0; index-- {
		if chain[index] != "" && !TrustedProxyConfig.IsTrustedSource(chain[index]) {
			return chain[index]
		}
	}
	return ""
}

// normalizeIP strips the port some proxies append, and the brackets IPv6 needs
// when a port is present.
func normalizeIP(entry string) string {
	if net.ParseIP(entry) != nil {
		return entry
	}
	if host, _, err := net.SplitHostPort(entry); err == nil {
		if net.ParseIP(host) != nil {
			return host
		}
	}
	return strings.Trim(entry, "[]")
}

func getContentType(r *http.Request) string {
	contentType := r.Header.Get("Accept")
	if contentType == "" {
		contentType = r.Header.Get("Content-Type")
	}
	return contentType
}
func allowedOrigin(origins []string, origin string) bool {
	return slices.Contains(origins, origin)
}

func RespondWithError(w http.ResponseWriter, r *http.Request, statusCode int, logMessage string, origins []string, contentType string) {
	// Set the message for the error response
	message := fmt.Sprintf("%d %s", statusCode, http.StatusText(statusCode))
	if len(logMessage) > 0 {
		message = logMessage
	}

	// Set Access-Control-Allow-Origin header if the origin is allowed
	if allowedOrigin(origins, r.Header.Get("Origin")) {
		w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
		w.Header().Add("Vary", "Origin")
	}
	w.Header().Del("Content-Length")
	switch contentType {
	case "application/json":
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)

		if isJson(message) {
			_, err := w.Write([]byte(message))
			if err != nil {
				logger.Error("Error writing JSON error message", "error", err)
			}
			return
		}

		// Otherwise encode structured JSON error response
		err := json.NewEncoder(w).Encode(ProxyResponseError{
			Success:    false,
			StatusCode: statusCode,
			Error:      message,
		})
		if err != nil {
			logger.Error("Error encoding JSON response", "error", err)
		}
		return

	case "application/xhtml+xml", "application/xml", "text/xml":
		w.Header().Set("Content-Type", "application/xhtml+xml")
		w.WriteHeader(statusCode)

		xmlResponse := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
			<error>
				<success>false</success>
				<statusCode>%d</statusCode>
				<error>%s</error>
			</error>`, statusCode, html.EscapeString(message))

		_, err := w.Write([]byte(xmlResponse))
		if err != nil {
			logger.Error("Error writing XML response", "error", err)
		}
		return

	default:
		http.Error(w, message, statusCode)
		return
	}
}

// RespondWithErrorHTML adds support for responding with HTML files.
func RespondWithErrorHTML(
	w http.ResponseWriter,
	r *http.Request,
	statusCode int,
	logMessage string,
	origins []string,
	contentType string,
	htmlFile string,
) {
	// Handle CORS
	if allowedOrigin(origins, r.Header.Get("Origin")) {
		w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
		w.Header().Add("Vary", "Origin")
	}
	w.Header().Del("Content-Length")

	if htmlFile != "" {
		serveHTMLFile(w, statusCode, htmlFile)
		return
	}

	if contentType == contentTypeHTML {
		serveHTMLString(w, statusCode, logMessage)
		return
	}
	RespondWithError(w, r, statusCode, logMessage, origins, contentType)
}

// isJson checks if the given string is valid JSON
func isJson(s string) bool {
	var js interface{}
	err := json.Unmarshal([]byte(s), &js)
	return err == nil
}

// compiledPatterns caches path patterns, including the ones that do not compile,
// so a pattern is compiled once rather than on every request and an unusable one
// is reported once rather than every time it is passed over.
var compiledPatterns sync.Map // pattern -> *compiledPattern

type compiledPattern struct {
	regex *regexp.Regexp
	err   error
}

func compilePattern(pattern string) *compiledPattern {
	if cached, ok := compiledPatterns.Load(pattern); ok {
		return cached.(*compiledPattern)
	}

	regex, err := regexp.Compile("(?i)" + anchorPattern(pattern))
	entry := &compiledPattern{regex: regex, err: err}
	if _, alreadyStored := compiledPatterns.LoadOrStore(pattern, entry); !alreadyStored && err != nil {
		logger.Warn("Path pattern is not a valid regular expression, matching it as a wildcard instead",
			"pattern", pattern, "regexForm", regexHint(pattern))
	}
	return entry
}

// anchorPattern ties a path pattern to the start of the path.
//
// Unanchored, "/admin" also matched "/x/admin" and "/x/y/administrator": a
// pattern meant to name a resource matched anywhere it appeared in the path,
// which is neither what an operator writes nor something they can predict. The
// anchor is start-only, so "/admin" still covers "/admin/settings" — a pattern
// that already carries its own "^" is left alone.
func anchorPattern(pattern string) string {
	if strings.HasPrefix(pattern, "^") {
		return pattern
	}
	return "^" + pattern
}

// regexHint rewrites a wildcard pattern as the regular expression that means
// the same thing, so the warning says what to change it to.
func regexHint(pattern string) string {
	var hint strings.Builder
	for index, character := range pattern {
		if character == '*' && (index == 0 || pattern[index-1] != '.') {
			hint.WriteString(".*")
			continue
		}
		hint.WriteRune(character)
	}
	return hint.String()
}

// checkRegexMatch checks if the given string matches any regex pattern from the
// list. A pattern that is not a regular expression is passed over rather than
// abandoning the whole list: one wildcard entry must not stop the regular
// expressions beside it from being matched.
func checkRegexMatch(input string, patterns []string) (bool, string) {
	for _, pattern := range patterns {
		compiled := compilePattern(pattern)
		if compiled.err != nil {
			continue
		}
		if compiled.regex.MatchString(input) {
			return true, pattern
		}
	}
	return false, ""
}

// isGuardedPathMatching is isPathMatching for the middlewares that decide
// whether a request is allowed through — the auth middlewares and the access
// blocklist.
//
// An empty paths list means "every path in the route". Falling through to
// isPathMatching would return false for an empty list, so an auth middleware
// written without paths: attached cleanly, logged nothing and authenticated no
// request at all. The safe reading of "no paths named" is all of them, which is
// also what RequestHeaders.appliesTo already assumes.
func isGuardedPathMatching(urlPath, prefix string, paths []string) bool {
	if len(paths) == 0 {
		return true
	}
	return isPathMatching(urlPath, prefix, paths)
}

// isPathMatching checks if the urlPath matches any regex pattern or static path from the list.
func isPathMatching(urlPath, prefix string, paths []string) bool {
	matched, _ := IsPathMatching(urlPath, prefix, paths)
	return matched
}

// IsPathMatching checks if the urlPath matches any regex pattern or static path from the list.
func IsPathMatching(urlPath, prefix string, paths []string) (bool, string) {
	for _, path := range paths {
		// Patterns are anchored to the start of the path, so a pattern written
		// relative to the route also has to be tried joined to the route
		// prefix — otherwise "/admin" on a route rooted at "/api" would stop
		// covering "/api/admin/settings".
		prefixed := util.ParseURLPath(prefix + path)
		if matched, _ := checkRegexMatch(urlPath, []string{path, prefixed}); matched {
			return true, path
		}
		if isMatchingPath(urlPath, path) || isMatchingPath(urlPath, prefixed) {
			return true, path
		}
	}

	return false, ""
}

// Helper function to determine if the request path is blocked.
//
// Matching is case-insensitive: many upstream servers and frameworks treat URL
// paths case-insensitively, so a case-sensitive comparison here would let a
// request like "/Admin" slip past an auth/block rule for "/admin" while still
// reaching the protected resource. Comparing case-insensitively fails safe.
func isMatchingPath(requestPath, blockedPath string) bool {
	// Handle exact match
	if strings.EqualFold(requestPath, blockedPath) {
		return true
	}
	// Handle wildcard match (e.g., /admin/* should block /admin and any subpath)
	if strings.HasSuffix(blockedPath, "/*") {
		basePath := strings.TrimSuffix(blockedPath, "/*")
		if hasPrefixFold(requestPath, basePath) {
			return true
		}
	}
	return false
}

// hasPrefixFold reports whether s starts with prefix, ignoring case.
func hasPrefixFold(s, prefix string) bool {
	return len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix)
}
func serveHTMLFile(w http.ResponseWriter, statusCode int, filePath string) {
	htmlCacheMu.RLock()
	buf, ok := htmlCache[filePath]
	htmlCacheMu.RUnlock()

	if !ok {
		// Load file
		data, err := os.ReadFile(filePath)
		if err != nil {
			logger.Error("Failed to read HTML file", "file", filePath, "error", err)
			fallbackHTML(w, statusCode)
			return
		}

		// Store in cache
		htmlCacheMu.Lock()
		htmlCache[filePath] = data
		htmlCacheMu.Unlock()

		buf = data
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(statusCode)

	if _, err := w.Write(buf); err != nil {
		logger.Error("Error writing HTML file to response", "error", err)
	}
}
func serveHTMLString(w http.ResponseWriter, statusCode int, htmlContent string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(statusCode)

	if htmlContent == "" {
		htmlContent = fmt.Sprintf("<h1>%d %s</h1>", statusCode, http.StatusText(statusCode))
	}

	if _, err := w.Write([]byte(htmlContent)); err != nil {
		logger.Error("Error writing inline HTML response", "error", err)
	}
}

func fallbackHTML(w http.ResponseWriter, statusCode int) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(statusCode)

	fallback := fmt.Sprintf("<h1>%d %s</h1>", statusCode, http.StatusText(statusCode))
	_, err := w.Write([]byte(fallback))
	if err != nil {
		return
	}
}
