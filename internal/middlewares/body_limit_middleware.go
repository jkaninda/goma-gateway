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
	"io"
	"net/http"
	"strings"
)

type BodyLimit struct {
	MaxBytes int64
}

func (b BodyLimit) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		contentType := r.Header.Get("Content-Type")
		// Create a new limited reader with the specified limit
		lr := &io.LimitedReader{R: r.Body, N: b.MaxBytes + 1}
		// Read the entire body into a buffer
		body, err := io.ReadAll(lr)
		if err != nil {
			http.Error(w, "Error reading body", http.StatusInternalServerError)
			return
		}

		// Check if the body exceeded the limit
		if lr.N <= 0 {
			logger.Debug("Request body too large", "limit", b.MaxBytes)
			RespondWithError(w, r, http.StatusRequestEntityTooLarge, fmt.Sprintf("Request body too large (limit %d bytes)", b.MaxBytes), nil, contentType)
			return
		}

		// Replace the original body with the limited body
		r.Body = io.NopCloser(strings.NewReader(string(body)))

		// Call the next handler
		next.ServeHTTP(w, r)
	})
}
