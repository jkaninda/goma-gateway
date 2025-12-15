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
	"context"
	"github.com/google/uuid"
	goutils "github.com/jkaninda/go-utils"
	"github.com/jkaninda/goma-gateway/internal/middlewares"
	"net/http"
	"sort"
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
	request     *http.Request
	policies    []ResponseHeader
}

// newResponseRecorder creates a new responseRecorder
func newResponseRecorder(w http.ResponseWriter, r *http.Request, intercept bool, headers []ResponseHeader) *responseRecorder {
	return &responseRecorder{
		ResponseWriter: w,
		statusCode:     http.StatusOK,
		intercept:      intercept,
		header:         make(http.Header),
		body:           bytes.NewBuffer(nil),
		maxBodySize:    10 * 1024 * 1024, // 10MB
		policies:       headers,
		request:        r,
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

	// Apply header responseHeaders before writing headers
	rec.applyResponseHeaders()
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
	rec.ResponseWriter.Header().Del("Content-Length")
	rec.ResponseWriter.WriteHeader(rec.statusCode)
	if rec.body.Len() > 0 {
		_, _ = rec.ResponseWriter.Write(rec.body.Bytes())
		rec.body = nil // free buffer
	}
}

// Wrap intercepts responses based on the status code
func (p *ProxyMiddleware) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		startTime := time.Now()
		requestID := getRequestID(r)

		if isWebSocketRequest(r) || isSSE(r) {
			next.ServeHTTP(w, r)
			return
		}
		ip := middlewares.RealIP(r)
		if val := r.Context().Value(CtxRequestStartTime); val != nil {
			startTime = val.(time.Time)
		}
		if val := r.Context().Value(CtxRequestIDHeader); val != nil {
			requestID = val.(string)
		}

		intercept := p.Enabled && len(p.Errors) > 0
		rec := newResponseRecorder(w, r, intercept, p.headers)
		rec.Header().Set(RequestIDHeader, requestID)
		method := r.Method

		// Metrics
		if p.enableMetrics {
			logger.Debug("Metrics collection started")
			prometheusMetrics.GatewayTotalRequests.WithLabelValues(p.Name, method).Inc()

			// Deprecated metrics (backward compatibility)
			prometheusMetrics.TotalRequests.WithLabelValues(p.Name, method).Inc()

			// Update real-time visitors gauge
			if p.VisitorTracker != nil {
				p.VisitorTracker.AddVisitor(context.Background(), ip, r.UserAgent())
			}
		}

		next.ServeHTTP(rec, r)

		if p.enableMetrics {
			duration := time.Since(startTime).Seconds()
			statusStr := strconv.Itoa(rec.statusCode)
			prometheusMetrics.GatewayResponseStatus.WithLabelValues(statusStr, p.Name, method).Inc()
			prometheusMetrics.GatewayRequestDuration.WithLabelValues(p.Name, method).Observe(duration)

			// Deprecated metrics (backward compatibility)
			prometheusMetrics.ResponseStatus.WithLabelValues(statusStr, p.Name, method).Inc()
			prometheusMetrics.HttpDuration.WithLabelValues(p.Name, method).Observe(duration)

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
			"route", p.Name,
			"user_agent", r.UserAgent(),
		}
		if p.logRule != nil {
			logger.Debug("Appending custom log fields")
			p.appendCustomLogFields(&logFields, r)
		}

		if val := r.Context().Value(CtxSelectedBackend); val != nil {
			logFields = append(logFields, "backend", val)
		}

		if debugMode {
			debugFields := p.buildDebugFields(r, rec)
			logFields = append(logFields, debugFields...)

		}
		// Handle response interception
		if intercept && !rec.skipBuffer {
			if p.handleResponseInterception(rec, w, r) {
				prometheusMetrics.GatewayTotalErrorsIntercepted.WithLabelValues(p.Name, strconv.Itoa(rec.statusCode)).Inc()
				logProxyResponse(rec.statusCode, "Proxied request", logFields...)
				return
			}
		}
		logProxyResponse(rec.statusCode, "Proxied request", logFields...)
	})
}
func (p *ProxyMiddleware) handleResponseInterception(rec *responseRecorder, w http.ResponseWriter, r *http.Request) bool {
	if ok, messageOrFile, serveFile := middlewares.ShouldIntercept(rec.statusCode, p.Errors); ok {
		logger.Debug("Response intercepted",
			"status", rec.statusCode,
			"route", p.Name,
			"reason", "matched_error_condition",
		)
		contentType := p.ContentType
		if contentType == "" {
			contentType = getContentType(r)
		}
		// Flush headers before responding with error
		rec.flushHeaders()
		if serveFile {
			middlewares.RespondWithErrorHTML(w, r, rec.statusCode, messageOrFile, p.Origins, contentType, messageOrFile)
			return true
		}
		middlewares.RespondWithError(w, r, rec.statusCode, messageOrFile, p.Origins, contentType)
		return true
	}

	logger.Debug("Response not intercepted; sending buffered response",
		"status", rec.statusCode,
		"route", p.Name,
		"reason", "no_matching_error_condition",
	)
	// Flush the buffered response
	rec.flushBufferedResponse()
	return false
}

// buildDebugFields creates debug log fields
func (p *ProxyMiddleware) buildDebugFields(r *http.Request, rec *responseRecorder) []any {
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
func (p *ProxyMiddleware) appendCustomLogFields(fields *[]any, r *http.Request) {
	if p.logRule == nil {
		return
	}
	for _, hKey := range p.logRule.Headers {
		if val := r.Header.Get(hKey); val != "" {
			*fields = append(*fields, strings.ToLower(hKey), val)
		}
	}

	q := r.URL.Query()
	for _, qKey := range p.logRule.Query {
		if val := q.Get(qKey); val != "" {
			*fields = append(*fields, qKey, val)
		}
	}
	for _, cKey := range p.logRule.Cookies {
		if c, err := r.Cookie(cKey); err == nil {
			*fields = append(*fields, cKey, c.Value)
		}
	}

}

func (rec *responseRecorder) applyResponseHeaders() {
	sortedResponseHeaders := rec.getSortedResponseHeaders()
	if len(sortedResponseHeaders) == 0 {
		logger.Debug("No responseHeaders configured; skipping header application")
		return
	}
	logger.Debug("Applying responseHeaders", "count", len(sortedResponseHeaders))
	headers := rec.Header()

	// Apply each responseHeader in order
	for _, header := range sortedResponseHeaders {
		logger.Debug("Applying header",
			"header", header.Name,
			"path", rec.request.URL.Path,
		)

		// Apply custom headers (set, override, or remove)
		for key, value := range header.SetHeaders {
			if value == "" {
				headers.Del(key)
				logger.Debug("Removed header",
					"header", key,
					"header", header.Name,
				)
				continue
			}

			// Only apply most headers on successful responses
			// Exception: Allow explicit Cache-Control overrides for error pages
			if rec.statusCode != http.StatusOK && !strings.EqualFold(key, "Cache-Control") {
				logger.Debug("Skipping header (non-200 status)",
					"header", key,
					"status", rec.statusCode,
					"header", header.Name,
				)
				continue
			}

			headers.Set(key, value)
			logger.Debug("Set/overridden header",
				"header", key,
				"value", value,
				"header", header.Name,
			)
		}

		// Apply dedicated CacheControl field (only for successful responses)
		if header.CacheControl != "" && rec.statusCode == http.StatusOK {
			headers.Set("Cache-Control", header.CacheControl)
			logger.Debug("Applied CacheControl from header field",
				"value", header.CacheControl,
				"header", header.Name,
			)
		}

		// Apply CORS if configured
		if header.Cors != nil && header.Cors.Enabled {
			rec.applyCorsHeaders(header)
		}
	}
}

// getSortedResponseHeaders returns headers sorted by specificity
// More general paths are applied first, more specific paths last
func (rec *responseRecorder) getSortedResponseHeaders() []ResponseHeader {
	if len(rec.policies) == 0 {
		return nil
	}

	// Create a copy to avoid modifying the original
	sorted := make([]ResponseHeader, len(rec.policies))
	copy(sorted, rec.policies)

	// Sort by path length (shorter = more general = applied first)
	sort.Slice(sorted, func(i, j int) bool {
		return len(sorted[i].MatchedPath) < len(sorted[j].MatchedPath)
	})

	return sorted
}

// applyCorsHeaders applies CORS headers from a specific ResponseHeader
// Gateway CORS headers always override backend CORS headers
func (rec *responseRecorder) applyCorsHeaders(policy ResponseHeader) {
	cors := policy.Cors
	if cors == nil || !cors.Enabled {
		return
	}

	logger.Debug("======== Applying responseHeader", "count", len(rec.policies))

	origin := rec.request.Header.Get("Origin")

	// Skip CORS handling if the origin is not allowed
	if !allowedOrigin(cors.Origins, origin) {
		logger.Debug("Origin not allowed",
			"origin", origin,
			"policy", policy.Name,
			"allowed_origins", cors.Origins,
		)
		return
	}

	headers := rec.Header()

	// Set allowed origin (overrides any backend CORS)
	headers.Set("Access-Control-Allow-Origin", origin)

	// Set allow credentials header if configured
	if cors.AllowCredentials {
		headers.Set("Access-Control-Allow-Credentials", "true")
	}

	// Handle allowed headers
	if len(cors.AllowedHeaders) > 0 {
		headers.Set("Access-Control-Allow-Headers", strings.Join(cors.AllowedHeaders, ", "))
	} else if reqHeaders := rec.request.Header.Get("Access-Control-Request-Headers"); reqHeaders != "" {
		headers.Set("Access-Control-Allow-Headers", reqHeaders)
	}

	// Handle allowed methods
	if len(cors.AllowMethods) > 0 {
		headers.Set("Access-Control-Allow-Methods", strings.Join(cors.AllowMethods, ", "))
	} else if reqMethod := rec.request.Header.Get("Access-Control-Request-Method"); reqMethod != "" {
		headers.Set("Access-Control-Allow-Methods", reqMethod)
	}

	// Set exposed headers if configured
	if len(cors.ExposeHeaders) > 0 {
		headers.Set("Access-Control-Expose-Headers", strings.Join(cors.ExposeHeaders, ", "))
	}

	// Set max age for preflight cache if configured
	if cors.MaxAge > 0 {
		headers.Set("Access-Control-Max-Age", strconv.Itoa(cors.MaxAge))
	}

	for k, v := range cors.Headers {
		if !strings.EqualFold(k, "Access-Control-Allow-Origin") {
			if v == "" {
				headers.Del(k)
			} else {
				headers.Set(k, v)
			}
		}
	}

	logger.Debug("CORS headers applied",
		"policy", policy.Name,
		"origin", origin,
		"credentials", cors.AllowCredentials,
		"methods", cors.AllowMethods,
	)
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
