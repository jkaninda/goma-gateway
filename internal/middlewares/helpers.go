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
	"net/http"
	"slices"
)

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
func RespondWithError(w http.ResponseWriter, statusCode int, logMessage string) {
	message := http.StatusText(statusCode)
	if len(logMessage) != 0 {
		message = logMessage
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	err := json.NewEncoder(w).Encode(ProxyResponseError{
		Success: false,
		Code:    statusCode,
		Message: message,
	})
	if err != nil {
		return
	}

}
