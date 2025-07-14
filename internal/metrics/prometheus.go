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

package metrics

import (
	"github.com/jkaninda/logger"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// PrometheusMetrics holds all Prometheus metrics
type PrometheusMetrics struct {
	TotalRequests  *prometheus.CounterVec
	ResponseStatus *prometheus.CounterVec
	HttpDuration   *prometheus.HistogramVec
}

// NewPrometheusMetrics creates a new set of Prometheus metrics
func NewPrometheusMetrics() *PrometheusMetrics {
	return &PrometheusMetrics{
		TotalRequests: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "http_requests_total",
				Help: "Total number of HTTP requests",
			},
			[]string{"name", "path", "method"},
		),
		ResponseStatus: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "http_response_status_total",
				Help: "Total number of HTTP responses by status code",
			},
			[]string{"status", "name", "path", "method"},
		),
		HttpDuration: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "http_request_duration_seconds",
				Help:    "Duration of HTTP requests in seconds",
				Buckets: prometheus.DefBuckets,
			},
			[]string{"name", "path", "method"},
		),
	}
}

// PrometheusRoute represents a route configuration for metrics
type PrometheusRoute struct {
	Name string
	Path string
}

// responseWriter wraps http.ResponseWriter to capture status code
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	if rw.statusCode == 0 {
		rw.statusCode = http.StatusOK
	}
	return rw.ResponseWriter.Write(b)
}

// PrometheusMiddleware creates a middleware that records Prometheus metrics
func (pr PrometheusRoute) PrometheusMiddleware(metrics *PrometheusMetrics) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			logger.Debug(">>> Calling PrometheusMiddleware", "path", r.URL.Path, "method", r.Method)
			// Determine the path for metrics
			path := pr.Path
			if path == "" {
				if route := mux.CurrentRoute(r); route != nil {
					if template, err := route.GetPathTemplate(); err == nil {
						path = template
					}
				}
				// Fallback to request URL path if no route template
				if path == "" {
					path = r.URL.Path
				}
			}

			// Wrap the response writer to capture status code
			wrapped := &responseWriter{
				ResponseWriter: w,
				statusCode:     0,
			}

			// Record request
			method := r.Method
			metrics.TotalRequests.WithLabelValues(pr.Name, path, method).Inc()

			next.ServeHTTP(wrapped, r)

			// Record response metrics
			statusCode := wrapped.statusCode
			if statusCode == 0 {
				statusCode = http.StatusOK
			}
			duration := time.Since(start).Seconds()
			statusStr := strconv.Itoa(statusCode)

			metrics.ResponseStatus.WithLabelValues(statusStr, pr.Name, path, method).Inc()
			metrics.HttpDuration.WithLabelValues(pr.Name, path, method).Observe(duration)
		})
	}
}
