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
	"github.com/jkaninda/goma-gateway/util"
	"html"
	"net"
	"net/http"
	"os"
	"regexp"
	"slices"
	"strings"
	"sync"
)

var htmlCache = make(map[string][]byte)
var htmlCacheMu sync.RWMutex

// RealIP extracts the real IP address of the client from the HTTP request.
func RealIP(r *http.Request) string {
	remoteIP, _, _ := net.SplitHostPort(r.RemoteAddr)

	if !TrustedProxyConfig.Enabled {
		if remoteIP != "" {
			return remoteIP
		}
		return r.RemoteAddr
	}

	// Check if request actually came through a trusted proxy
	if len(TrustedProxyConfig.TrustedProxies) > 0 {
		if !TrustedProxyConfig.IsTrustedSource(remoteIP) {
			return remoteIP
		}
	}

	//  configured IP headers
	for _, header := range TrustedProxyConfig.IPHeaders {
		if val := r.Header.Get(header); val != "" {
			ips := strings.Split(val, ",")
			for _, ip := range ips {
				trimmed := strings.TrimSpace(ip)
				if trimmed != "" {
					return trimmed
				}
			}
		}
	}
	if remoteIP != "" {
		return remoteIP
	}
	return r.RemoteAddr
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
	}
	w.Header().Del("Content-Length")

	if htmlFile != "" {
		serveHTMLFile(w, statusCode, htmlFile)
		return
	}

	if contentType == "text/html" {
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

// checkRegexMatch checks if the given string matches any regex pattern from the list.
func checkRegexMatch(input string, patterns []string) (bool, string, error) {
	for _, pattern := range patterns {
		matcher, err := regexp.Compile(pattern)
		if err != nil {
			return false, "", fmt.Errorf("invalid regex pattern: %s, error: %w", pattern, err)
		}
		if matcher.MatchString(input) {
			return true, pattern, nil
		}
	}
	return false, "", nil
}

// isPathMatching checks if the urlPath matches any regex pattern or static path from the list.
func isPathMatching(urlPath, prefix string, paths []string) bool {
	// Check if the string matches any regex pattern
	if matched, _, err := checkRegexMatch(urlPath, paths); err == nil && matched {
		return true
	} else if err != nil {
		logger.Error("Error", "error", err.Error())
	}

	// Check without and with the route prefix
	for _, path := range paths {
		if isMatchingPath(urlPath, path) || isMatchingPath(urlPath, util.ParseURLPath(prefix+path)) {
			return true
		}
	}

	return false
}

// IsPathMatching checks if the urlPath matches any regex pattern or static path from the list.
func IsPathMatching(urlPath, prefix string, paths []string) (bool, string) {
	// Check if the string matches any regex pattern
	if matched, path, err := checkRegexMatch(urlPath, paths); err == nil && matched {
		return true, path
	} else if err != nil {
		logger.Error("Error", "error", err.Error())
	}

	// Check without and with the route prefix
	for _, path := range paths {
		if isMatchingPath(urlPath, path) || isMatchingPath(urlPath, util.ParseURLPath(prefix+path)) {
			return true, path
		}
	}

	return false, ""
}

// Helper function to determine if the request path is blocked
func isMatchingPath(requestPath, blockedPath string) bool {
	// Handle exact match
	if requestPath == blockedPath {
		return true
	}
	// Handle wildcard match (e.g., /admin/* should block /admin and any subpath)
	if strings.HasSuffix(blockedPath, "/*") {
		basePath := strings.TrimSuffix(blockedPath, "/*")
		if strings.HasPrefix(requestPath, basePath) {
			return true
		}
	}
	return false
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
