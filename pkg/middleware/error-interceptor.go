package middleware

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
import (
	"bytes"
	"encoding/json"
	"github.com/jkaninda/goma-gateway/internal/logger"
	"io"
	"net/http"
)

// InterceptErrors contains backend status code errors to intercept
type InterceptErrors struct {
	Errors []int
}

// responseRecorder intercepts the response body and status code
type responseRecorder struct {
	http.ResponseWriter
	statusCode int
	body       *bytes.Buffer
}

func newResponseRecorder(w http.ResponseWriter) *responseRecorder {
	return &responseRecorder{
		ResponseWriter: w,
		statusCode:     http.StatusOK,
		body:           &bytes.Buffer{},
	}
}

func (rec *responseRecorder) WriteHeader(code int) {
	rec.statusCode = code
}

func (rec *responseRecorder) Write(data []byte) (int, error) {
	return rec.body.Write(data)
}

// ErrorInterceptor Middleware intercepts backend errors
func (intercept InterceptErrors) ErrorInterceptor(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := newResponseRecorder(w)
		next.ServeHTTP(rec, r)
		if canIntercept(rec.statusCode, intercept.Errors) {
			logger.Error("Backend error")
			logger.Error("An error occurred in the backend, %d", rec.statusCode)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(rec.statusCode)
			err := json.NewEncoder(w).Encode(ProxyResponseError{
				Success: false,
				Code:    rec.statusCode,
				Message: http.StatusText(rec.statusCode),
			})
			if err != nil {
				return
			}
		} else {
			// No error: write buffered response to client
			w.WriteHeader(rec.statusCode)
			_, err := io.Copy(w, rec.body)
			if err != nil {
				return
			}

		}

	})
}
func canIntercept(code int, errors []int) bool {
	for _, er := range errors {
		if er == code {
			return true
		}
		continue

	}
	return false
}
