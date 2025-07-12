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
	intercepted bool
	bodySize    int64
	maxBodySize int64 // Maximum body size to buffer (50MB)
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
		maxBodySize:    50 * 1024 * 1024, // 50MB limit
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

	// Check if we should bypass buffering based on content type and headers
	if rec.intercept && shouldBypassBodyIntercept(rec.header) {
		rec.skipBuffer = true
	}

	// Only write headers to original response if not intercepting or bypassing
	if !rec.intercept || rec.skipBuffer {
		copyHeaders(rec.ResponseWriter.Header(), rec.header)
		if !rec.wroteHeader {
			rec.ResponseWriter.WriteHeader(code)
		}
	}
}

func (rec *responseRecorder) Write(data []byte) (int, error) {
	if !rec.wroteHeader {
		rec.wroteHeader = true
		rec.WriteHeader(rec.statusCode)
	}

	// If not intercepting or bypassing, write directly
	if !rec.intercept || rec.skipBuffer {
		return rec.ResponseWriter.Write(data)
	}

	// If intercepting, check size limits and buffer accordingly
	dataSize := int64(len(data))

	if rec.bodySize+dataSize <= rec.maxBodySize {
		rec.bodySize += dataSize
		return rec.body.Write(data)
	} else {
		rec.skipBuffer = true
		if rec.body.Len() > 0 {
			copyHeaders(rec.ResponseWriter.Header(), rec.header)
			rec.wroteHeader = true
			rec.ResponseWriter.WriteHeader(rec.statusCode)
			_, err := rec.ResponseWriter.Write(rec.body.Bytes())
			if err != nil {
				return 0, err
			}
			rec.body = nil // Free the buffer memory
		}
		// Write current data directly to original response
		return rec.ResponseWriter.Write(data)
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

		if val := r.Context().Value(CtxRequestStartTime); val != nil {
			startTime = val.(time.Time)
		}
		if val := r.Context().Value(CtxRequestIDHeader); val != nil {
			requestID = val.(string)
		}
		rec.Header().Set(RequestIDHeader, requestID)

		next.ServeHTTP(rec, r)

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

		if intercept {
			if ok, message := middlewares.ShouldIntercept(rec.statusCode, h.Errors); ok {
				rec.intercepted = true
				logger.Debug("================== Intercepting response")

				if !rec.skipBuffer {
					copyHeaders(w.Header(), rec.header)
					logProxyResponse(rec.statusCode, "Proxied request resulted in error", logFields...)
					middlewares.RespondWithError(w, r, rec.statusCode, message, h.Origins, contentType)
					return
				} else {
					logger.Debug("Response body too large for interception, already written")
				}
			} else {
				logger.Debug("============ Response not intercepted")

				// Not intercepting
				if !rec.skipBuffer {
					copyHeaders(w.Header(), rec.header)
					if rec.wroteHeader {
						w.WriteHeader(rec.statusCode)
					}
					if rec.body != nil && rec.body.Len() > 0 {
						_, err := w.Write(rec.body.Bytes())
						if err != nil {
							return
						}
					}
				}
			}
		}
		logProxyResponse(rec.statusCode, "Proxied request", logFields...)
	})
}

func copyHeaders(dst, src http.Header) {
	for k := range dst {
		delete(dst, k)
	}
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
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
		if size, err := strconv.Atoi(contentLengthStr); err == nil && size > 50*1024*1024 { // 50MB
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
