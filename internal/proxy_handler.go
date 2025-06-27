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

package internal

import (
	"bytes"
	"github.com/google/uuid"
	goutils "github.com/jkaninda/go-utils"
	"github.com/jkaninda/goma-gateway/internal/middlewares"
	"io"
	"net/http"
	"time"
)

// responseRecorder is a custom http.ResponseWriter that captures the response status code and body
type responseRecorder struct {
	http.ResponseWriter
	statusCode int
	body       *bytes.Buffer
}

// newResponseRecorder creates a new responseRecorder
func newResponseRecorder(w http.ResponseWriter) *responseRecorder {
	return &responseRecorder{
		ResponseWriter: w,
		statusCode:     http.StatusOK,
		body:           &bytes.Buffer{},
	}
}

// WriteHeader writes the status code to the response
func (rec *responseRecorder) WriteHeader(code int) {
	rec.statusCode = code
}

// ProxyHandler proxies requests to the backend
func (rec *responseRecorder) Write(data []byte) (int, error) {
	return rec.body.Write(data)
}

// ProxyHandler intercepts responses based on the status code
func (h ProxyHandler) handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		startTime := time.Now()
		requestID := getRequestID(r)

		if isWebSocketRequest(r) || isSSE(r) {
			// Skip for WebSocket upgrades or Server-Sent Events
			next.ServeHTTP(w, r)
			return
		}

		// Determine content type
		contentType := h.ContentType
		if contentType == "" {
			contentType = r.Header.Get("Content-Type")
		}

		// Get request content length
		contentLength := r.Header.Get("Content-Length")
		if contentLength == "" {
			contentLength = "0"
		}

		// Record the response for interception
		rec := newResponseRecorder(w)
		next.ServeHTTP(rec, r)
		// Delete server header
		rec.Header().Del("Server")
		rec.Header().Set("Proxied-By", GatewayName)
		rec.Header().Set(RequestIDHeader, requestID)

		// Retrieve the request start time from context
		if val := r.Context().Value(CtxRequestStartTime); val != nil {
			startTime = val.(time.Time)
		}
		if val := r.Context().Value(CtxRequestIDHeader); val != nil {
			requestID = val.(string)
		}
		formatted := goutils.FormatDuration(time.Since(startTime), 2)

		logFields := []any{
			"method", r.Method,
			"url", r.URL.Path,
			"host", r.Host,
			"status", rec.statusCode,
			"duration", formatted,
			"route", h.Name,
			"client_ip", getRealIP(r),
			"request_id", requestID,
			"content_length", contentLength,
			"user_agent", r.UserAgent(),
		}

		// No interception logic needed
		if !h.Enabled || len(h.Errors) == 0 {
			logProxyResponse(rec.statusCode, "Proxied request", logFields...)
			// Copy recorded response to the client
			writeResponse(w, rec)
			return
		}

		// Check if the response should be intercepted
		if ok, message := middlewares.CanIntercept(rec.statusCode, h.Errors); ok {
			logProxyResponse(rec.statusCode, "Proxied request resulted in error", logFields...)
			middlewares.RespondWithError(w, r, rec.statusCode, message, h.Origins, contentType)
			return
		}

		logProxyResponse(rec.statusCode, "Proxied request", logFields...)
		writeResponse(w, rec)
	})
}

// writeResponse writes the recorded response to the client
func writeResponse(w http.ResponseWriter, rec *responseRecorder) {
	w.WriteHeader(rec.statusCode)
	_, _ = io.Copy(w, rec.body)
}

func getRequestID(r *http.Request) string {
	requestID := r.Header.Get("X-Request-ID")
	if requestID != "" {
		return requestID
	}
	return uuid.NewString()
}
func logProxyResponse(status int, msg string, fields ...any) {
	switch {
	case status >= 500:
		logger.Error(msg, fields...)
	case status >= 400:
		logger.Warn(msg, fields...)
	default:
		logger.Info(msg, fields...)
	}
}
