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
	"net/http"
	"strconv"
	"strings"
	"time"
)

// responseRecorder is a custom http.ResponseWriter that captures the response status code and body
type responseRecorder struct {
	http.ResponseWriter
	statusCode  int
	body        *bytes.Buffer
	header      http.Header
	intercept   bool
	wroteHeader bool
	bodySize    int64
	maxBodySize int64
	skipBuffer  bool
}

// newResponseRecorder creates a new responseRecorder
func newResponseRecorder(w http.ResponseWriter, intercept bool) *responseRecorder {
	return &responseRecorder{
		ResponseWriter: w,
		statusCode:     http.StatusOK,
		intercept:      intercept,
		header:         make(http.Header),
		body:           bytes.NewBuffer(nil),
		maxBodySize:    10 * 1024 * 1024, // 10MB
	}
}

func (rec *responseRecorder) Header() http.Header {
	return rec.header
}

// WriteHeader writes the status code to the response
func (rec *responseRecorder) WriteHeader(code int) {
	if rec.wroteHeader {
		return
	}
	rec.statusCode = code
	rec.wroteHeader = true

	rec.header.Del("Server")
	rec.header.Set("Proxied-By", GatewayName)

	if rec.intercept && shouldBypassBodyIntercept(rec.header) {
		rec.skipBuffer = true
	}

	if !rec.intercept || rec.skipBuffer {
		rec.flushHeaders()
		rec.ResponseWriter.WriteHeader(code)
	}
}

func (rec *responseRecorder) Write(data []byte) (int, error) {
	if !rec.wroteHeader {
		rec.WriteHeader(rec.statusCode)
	}

	if !rec.intercept || rec.skipBuffer {
		return rec.ResponseWriter.Write(data)
	}

	if rec.bodySize+int64(len(data)) <= rec.maxBodySize {
		rec.bodySize += int64(len(data))
		return rec.body.Write(data)
	}

	// Body too large, flush what's buffered and continue unbuffered
	rec.skipBuffer = true
	rec.flushBufferedResponse()
	return rec.ResponseWriter.Write(data)
}
func (rec *responseRecorder) flushHeaders() {
	dst := rec.ResponseWriter.Header()
	for k := range dst {
		delete(dst, k)
	}
	for k, vv := range rec.header {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func (rec *responseRecorder) flushBufferedResponse() {
	rec.flushHeaders()
	rec.ResponseWriter.WriteHeader(rec.statusCode)
	if rec.body.Len() > 0 {
		_, _ = rec.ResponseWriter.Write(rec.body.Bytes())
		rec.body = nil // free buffer
	}
}

// Wrap intercepts responses based on the status code
func (h *ProxyMiddleware) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		startTime := time.Now()
		requestID := getRequestID(r)

		if isWebSocketRequest(r) || isSSE(r) {
			next.ServeHTTP(w, r)
			return
		}
		ip := getRealIP(r)
		path := h.Path
		if val := r.Context().Value(CtxRequestStartTime); val != nil {
			startTime = val.(time.Time)
		}
		if val := r.Context().Value(CtxRequestIDHeader); val != nil {
			requestID = val.(string)
		}

		intercept := h.Enabled && len(h.Errors) > 0
		rec := newResponseRecorder(w, intercept)
		rec.Header().Set(RequestIDHeader, requestID)
		method := r.Method

		// Metrics
		if h.enableMetrics {
			logger.Debug("Metrics collection started")
			prometheusMetrics.TotalRequests.WithLabelValues(h.Name, path, method).Inc()
			prometheusMetrics.GatewayTotalRequests.WithLabelValues(h.Name, path, method).Inc()
		}

		next.ServeHTTP(rec, r)

		if h.enableMetrics {
			duration := time.Since(startTime).Seconds()
			statusStr := strconv.Itoa(rec.statusCode)
			requestBytes := r.ContentLength
			prometheusMetrics.ResponseStatus.WithLabelValues(statusStr, h.Name, path, method).Inc()
			prometheusMetrics.HttpDuration.WithLabelValues(h.Name, path, method).Observe(duration)
			prometheusMetrics.HTTPRequestSize.WithLabelValues(h.Name, path, method).Observe(float64(requestBytes))

			logger.Debug("Metrics recorded",
				"status", statusStr,
				"duration", duration,
			)

		}

		// Log core request info
		logFields := []any{
			"request_id", requestID,
			"method", method,
			"url", r.URL.Path,
			"http_version", r.Proto,
			"host", r.Host,
			"client_ip", ip,
			"referer", r.Referer(),
			"status", rec.statusCode,
			"duration", goutils.FormatDuration(time.Since(startTime), 2),
			"route", h.Name,
			"user_agent", r.UserAgent(),
		}

		if val := r.Context().Value(CtxSelectedBackend); val != nil {
			logFields = append(logFields, "backend", val)
		}

		if debugMode {
			debugFields := h.buildDebugFields(r, rec)
			logFields = append(logFields, debugFields...)

		}
		// Handle response interception
		if intercept && !rec.skipBuffer {
			if h.handleResponseInterception(rec, w, r) {
				logProxyResponse(rec.statusCode, "Proxied request", logFields...)
				return
			}
		}
		logProxyResponse(rec.statusCode, "Proxied request", logFields...)
	})
}
func (h *ProxyMiddleware) handleResponseInterception(rec *responseRecorder, w http.ResponseWriter, r *http.Request) bool {
	if ok, message := middlewares.ShouldIntercept(rec.statusCode, h.Errors); ok {
		logger.Debug("Response intercepted",
			"status", rec.statusCode,
			"route", h.Name,
			"reason", "matched_error_condition",
		)
		contentType := h.ContentType
		if contentType == "" {
			contentType = r.Header.Get("Content-Type")
		}
		rec.flushHeaders()
		middlewares.RespondWithError(w, r, rec.statusCode, message, h.Origins, contentType)
		return true
	}

	logger.Debug("Response not intercepted; sending buffered response",
		"status", rec.statusCode,
		"route", h.Name,
		"reason", "no_matching_error_condition",
	)
	// Flush the buffered response
	rec.flushBufferedResponse()
	return false
}

// buildDebugFields creates debug log fields
func (h *ProxyMiddleware) buildDebugFields(r *http.Request, rec *responseRecorder) []any {
	contentLength := r.Header.Get("Content-Length")
	if contentLength == "" {
		contentLength = "0"
	}

	fields := []any{
		"request_content_length", contentLength,
		"response_body_size", rec.bodySize,
	}

	if len(r.Header) > 0 {
		fields = append(fields, "request_headers", sanitizeHeaders(r.Header))
	}
	if len(r.URL.Query()) > 0 {
		fields = append(fields, "query_params", r.URL.Query())
	}
	if len(rec.Header()) > 0 {
		fields = append(fields, "response_headers", sanitizeHeaders(rec.Header()))
	}

	return fields
}

// sanitizeHeaders removes sensitive headers from logging
func sanitizeHeaders(headers http.Header) map[string][]string {
	sanitized := make(map[string][]string)
	sensitiveHeaders := map[string]bool{
		"authorization": true,
		"cookie":        true,
		"set-cookie":    true,
		"x-api-key":     true,
		"x-auth-token":  true,
	}

	for key, values := range headers {
		lowerKey := strings.ToLower(key)
		if sensitiveHeaders[lowerKey] {
			sanitized[key] = []string{"[REDACTED]"}
		} else {
			sanitized[key] = values
		}
	}
	return sanitized
}

// shouldBypassBodyIntercept checks if we should bypass body interception based on content type and headers
func shouldBypassBodyIntercept(header http.Header) bool {
	contentDisposition := header.Get("Content-Disposition")
	contentType := header.Get("Content-Type")
	contentLengthStr := header.Get("Content-Length")

	// Skip file downloads
	if strings.Contains(contentDisposition, "attachment") {
		return true
	}

	// Skip binary content types, but allow JSON and XML
	if strings.HasPrefix(contentType, "application/") {
		if strings.Contains(contentType, "json") ||
			strings.Contains(contentType, "xml") ||
			strings.Contains(contentType, "text") {
			return false
		}
		return true
	}

	// Skip video and audio content
	if strings.HasPrefix(contentType, "video/") ||
		strings.HasPrefix(contentType, "audio/") {
		return true
	}

	// Skip large content based on Content-Length header
	if contentLengthStr != "" {
		if size, err := strconv.Atoi(contentLengthStr); err == nil && size > 10*1024*1024 { // 10MB
			return true
		}
	}

	return false
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
