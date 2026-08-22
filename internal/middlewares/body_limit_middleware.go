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
)

type BodyLimit struct {
	MaxBytes int64
}

func (b BodyLimit) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if b.MaxBytes <= 0 || r.Body == nil || r.Body == http.NoBody {
			next.ServeHTTP(w, r)
			return
		}

		// Reject on the declared length when there is one, so an oversized
		// upload is refused before any of it is read.
		if r.ContentLength > b.MaxBytes {
			b.reject(w, r)
			return
		}

		// MaxBytesReader enforces the limit as the body is read, so a handler
		// that streams never holds more than it consumes, and one that reads to
		// the end fails at the limit instead of buffering past it.
		r.Body = http.MaxBytesReader(w, r.Body, b.MaxBytes)

		next.ServeHTTP(w, r)
	})
}

func (b BodyLimit) reject(w http.ResponseWriter, r *http.Request) {
	logger.Debug("Request body too large", "limit", b.MaxBytes, "declared", r.ContentLength)
	RespondWithError(w, r, http.StatusRequestEntityTooLarge,
		fmt.Sprintf("Request body too large (limit %d bytes)", b.MaxBytes), nil, getContentType(r))
}
