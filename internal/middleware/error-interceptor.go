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
	"github.com/jkaninda/goma-gateway/pkg/logger"
	"io"
	"net/http"
	"slices"
)

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
			logger.Debug("Backend error")
			logger.Error("An error occurred from the backend with the status code: %d", rec.statusCode)
			//Update Origin Cors Headers
			if allowedOrigin(intercept.Origins, r.Header.Get("Origin")) {
				w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
			}
			RespondWithError(w, rec.statusCode, http.StatusText(rec.statusCode))
			return
		} else {
			// No error: write buffered response to client
			w.WriteHeader(rec.statusCode)
			_, err := io.Copy(w, rec.body)
			if err != nil {
				return
			}
			return

		}

	})
}
func canIntercept(code int, errors []int) bool {
	return slices.Contains(errors, code)
}
