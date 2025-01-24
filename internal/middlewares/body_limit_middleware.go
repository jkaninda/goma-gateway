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
	"io"
	"net/http"
)

type BodyLimit struct {
	MaxBytes int64 `yaml:"maxBytes"`
}

func (b BodyLimit) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, b.MaxBytes)

		// Attempt to read a small portion to trigger size validation
		_, err := io.CopyN(io.Discard, r.Body, b.MaxBytes+1)
		if err != nil {
			if err == http.ErrBodyReadAfterClose {
				http.Error(w, "Request body too large", http.StatusRequestEntityTooLarge)
				return
			}
		}

		// Reset body if within size
		r.Body = http.MaxBytesReader(w, r.Body, b.MaxBytes)

		next.ServeHTTP(w, r)
	})

}
