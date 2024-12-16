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
	"github.com/jkaninda/goma-gateway/pkg/logger"
	"html"
	"net/http"
	"slices"
)

// getRealIP returns user real IP
func getRealIP(r *http.Request) string {
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return ip
	}
	if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
		return ip
	}
	return r.RemoteAddr
}
func allowedOrigin(origins []string, origin string) bool {
	return slices.Contains(origins, origin)
}

// RespondWithError is a helper function to handle error responses with flexible content type
func RespondWithError(w http.ResponseWriter, r *http.Request, statusCode int, logMessage string, origins []string, contentType string) {
	// Set the message for the error response
	message := http.StatusText(statusCode)
	if len(logMessage) > 0 {
		message = logMessage
	}
	w.WriteHeader(statusCode)
	// Set Access-Control-Allow-Origin header if the origin is allowed
	if allowedOrigin(origins, r.Header.Get("Origin")) {
		w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
	}
	// Handle JSON content type
	if contentType == "application/json" {
		w.Header().Set("Content-Type", "application/json")

		// If the message is valid JSON, directly write the error response
		if isJson(message) {
			http.Error(w, message, statusCode)
			return
		}

		// Otherwise, write a structured JSON response
		err := json.NewEncoder(w).Encode(ProxyResponseError{
			Success: false,
			Status:  statusCode,
			Error:   message,
		})
		// Log the error if encoding the JSON fails
		if err != nil {
			logger.Error("Error encoding JSON response: %v", err)
		}
		return
	}
	// Handle XML content type
	if contentType == "application/xhtml+xml" {
		w.Header().Set("Content-Type", "application/xhtml+xml")
		xmlResponse := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
			<error>
				<success>false</success>
				<status>%d</status>
				<error>%s</error>
			</error>`, statusCode, html.EscapeString(message))
		_, err := w.Write([]byte(xmlResponse))
		if err != nil {
			logger.Error("Error writing XML response: %v", err)
		}
		return
	}

	// For non-JSON responses, use http.Error for a basic text error response
	http.Error(w, message, statusCode)
}

// isJson checks if the given string is valid JSON
func isJson(s string) bool {
	var js interface{}
	err := json.Unmarshal([]byte(s), &js)
	return err == nil
}
