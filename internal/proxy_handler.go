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
	"net/url"
	"strings"
	"time"
)

// responseRecorder is a custom http.ResponseWriter that captures the response status code and body
type responseRecorder struct {
	http.ResponseWriter
	statusCode int
	body       *bytes.Buffer
	intercept  bool
}

// newResponseRecorder creates a new responseRecorder
func newResponseRecorder(w http.ResponseWriter, intercept bool) *responseRecorder {
	return &responseRecorder{
		ResponseWriter: w,
		statusCode:     http.StatusOK,
		body: func() *bytes.Buffer {
			if intercept {
				return &bytes.Buffer{}
			}
			return nil
		}(),
		intercept: intercept,
	}
}

// WriteHeader writes the status code to the response
func (rec *responseRecorder) WriteHeader(code int) {
	rec.statusCode = code
	rec.ResponseWriter.WriteHeader(code)
}

// ProxyHandler proxies requests to the backend
func (rec *responseRecorder) Write(data []byte) (int, error) {
	if rec.intercept && rec.body != nil {
		return rec.body.Write(data)
	}
	return rec.ResponseWriter.Write(data)
}

// Wrap intercepts responses based on the status code
func (h *ProxyHandler) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		startTime := time.Now()
		requestID := getRequestID(r)

		if isWebSocketRequest(r) || isSSE(r) {
			next.ServeHTTP(w, r)
			return
		}

		contentType := h.ContentType
		if contentType == "" {
			contentType = r.Header.Get("Content-Type")
		}
		contentLength := r.Header.Get("Content-Length")
		if contentLength == "" {
			contentLength = "0"
		}

		intercept := h.Enabled && len(h.Errors) > 0
		rec := newResponseRecorder(w, intercept)

		next.ServeHTTP(rec, r)

		// Cleanup headers
		rec.Header().Del("Server")
		rec.Header().Set("Proxied-By", GatewayName)
		rec.Header().Set(RequestIDHeader, requestID)

		if val := r.Context().Value(CtxRequestStartTime); val != nil {
			startTime = val.(time.Time)
		}
		if val := r.Context().Value(CtxRequestIDHeader); val != nil {
			requestID = val.(string)
		}
		duration := goutils.FormatDuration(time.Since(startTime), 2)

		logFields := []any{
			"request_id", requestID,
			"method", r.Method,
			"url", r.URL.RequestURI(),
			"http_version", r.Proto,
			"host", r.Host,
			"client_ip", getRealIP(r),
			"referer", r.Referer(),
			"status", rec.statusCode,
			"duration", duration,
			"request_content_length", contentLength,
			"route", h.Name,
			"user_agent", r.UserAgent(),
		}
		if backend, ok := r.Context().Value(CtxSelectedBackend).(*url.URL); ok {
			logFields = append(logFields, "backend", backend.String())
		}

		// Handle error interception
		if intercept {
			if ok, message := middlewares.CanIntercept(rec.statusCode, h.Errors); ok {
				logProxyResponse(rec.statusCode, "Proxied request resulted in error", logFields...)
				middlewares.RespondWithError(w, r, rec.statusCode, message, h.Origins, contentType)
				return
			}
			writeResponse(w, rec)
		}
		logProxyResponse(rec.statusCode, "Proxied request", logFields...)
	})
}

// writeResponse writes the recorded response to the client
func writeResponse(w http.ResponseWriter, recorder *responseRecorder) {
	w.WriteHeader(recorder.statusCode)
	_, _ = io.Copy(w, recorder.body)
}

func getRequestID(r *http.Request) string {
	requestID := r.Header.Get("X-Request-ID")
	if requestID != "" {
		return requestID
	}
	return strings.ReplaceAll(uuid.New().String(), "-", "")
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
