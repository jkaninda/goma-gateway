package middlewares

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
		contentType := intercept.Interceptor.ContentType
		if contentType == "" {
			contentType = r.Header.Get("Content-Type")
		}

		// Check if the connection is a WebSocket
		if isWebSocketRequest(r) {
			next.ServeHTTP(w, r)
			return
		}
		rec := newResponseRecorder(w)
		next.ServeHTTP(rec, r)
		can, message := canIntercept(rec.statusCode, intercept.Interceptor.Errors)
		if can {
			logger.Error("%s %s resulted in error with status code %d", r.Method, r.URL.Path, rec.statusCode)
			RespondWithError(w, r, rec.statusCode, message, intercept.Origins, contentType)
			return
		} else {
			// No error: write buffered response to client
			_, err := io.Copy(w, rec.body)
			if err != nil {
				return
			}

		}

	})
}
func isWebSocketRequest(r *http.Request) bool {
	return r.Header.Get("Upgrade") == "websocket" && r.Header.Get("Connection") == "Upgrade"
}
func canIntercept(code int, routeErrors []RouteError) (bool, string) {
	for _, routeError := range routeErrors {
		if code == routeError.Code {
			if routeError.Body != "" {
				return true, routeError.Body
			}
			return true, http.StatusText(code)
		}
	}
	return false, ""
}
