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
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"os"
	"time"
)

// PrometheusMetrics defines all Prometheus metrics tracked by the gateway.
type PrometheusMetrics struct {
	// Deprecated: use GatewayTotalRequests instead.
	TotalRequests *prometheus.CounterVec

	// Deprecated: use GatewayResponseStatus instead.
	ResponseStatus *prometheus.CounterVec

	// Deprecated: use GatewayRequestDuration instead.
	HttpDuration *prometheus.HistogramVec

	// Total number of requests handled by the gateway, labeled by route name and method.
	GatewayTotalRequests *prometheus.CounterVec

	// Uptime of the gateway application, in seconds since startup.
	GatewayUptime prometheus.Gauge

	// Current number of active routes registered in the gateway.
	GatewayRoutesCount prometheus.Gauge

	// Current number of middlewares registered in the gateway.
	GatewayMiddlewaresCount prometheus.Gauge

	// Number of real-time active visitors connected to the gateway.
	GatewayRealTimeVisitorsCount prometheus.Gauge

	// Total number of errors intercepted by the gateway,
	// labeled by route name and HTTP status code.
	GatewayTotalErrorsIntercepted *prometheus.CounterVec

	// Duration of HTTP requests handled by the gateway in seconds,
	// labeled by route name and method.
	GatewayRequestDuration *prometheus.HistogramVec

	// Total number of HTTP responses sent by the gateway,
	// labeled by status code, route name, and method.
	GatewayResponseStatus *prometheus.CounterVec
}

// NewPrometheusMetrics initializes and registers all Prometheus metrics for the gateway.
func NewPrometheusMetrics(startTime time.Time, stop chan os.Signal) *PrometheusMetrics {
	pm := &PrometheusMetrics{
		GatewayUptime: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "gateway_uptime_seconds",
			Help: "Uptime of the gateway application in seconds since startup",
		}),
		GatewayRoutesCount: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "gateway_routes_count",
			Help: "Current number of registered routes in the gateway",
		}),
		GatewayMiddlewaresCount: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "gateway_middlewares_count",
			Help: "Current number of registered middlewares in the gateway",
		}),
		GatewayRealTimeVisitorsCount: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "gateway_realtime_visitors_count",
			Help: "Number of currently connected real-time active visitors",
		}),
		GatewayTotalRequests: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "gateway_requests_total",
				Help: "Total number of requests processed by the gateway",
			},
			[]string{"name", "method"},
		),
		GatewayResponseStatus: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "gateway_response_status_total",
				Help: "Total number of HTTP responses sent, labeled by status code, route name, and method",
			},
			[]string{"status", "name", "method"},
		),
		GatewayRequestDuration: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "gateway_request_duration_seconds",
				Help:    "Histogram of request durations in seconds",
				Buckets: prometheus.DefBuckets,
			},
			[]string{"name", "method"},
		),
		GatewayTotalErrorsIntercepted: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "gateway_total_errors_intercepted",
				Help: "Total number of errors intercepted, labeled by route name and status code",
			},
			[]string{"name", "status"},
		),

		// Deprecated metrics (backward compatibility)
		TotalRequests: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "http_requests_total",
				Help: "Deprecated: use gateway_requests_total instead",
			},
			[]string{"name", "method"},
		),
		ResponseStatus: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "http_response_status_total",
				Help: "Deprecated: use gateway_response_status_total instead",
			},
			[]string{"status", "name", "method"},
		),
		HttpDuration: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "http_request_duration_seconds",
				Help:    "Deprecated: use gateway_request_duration_seconds instead",
				Buckets: prometheus.DefBuckets,
			},
			[]string{"name", "method"},
		),
	}

	// Start background goroutine to track uptime until the stop signal is received.
	go pm.trackUptime(startTime, stop)

	return pm
}

// Continuously updates the uptime gauge
func (pm *PrometheusMetrics) trackUptime(startTime time.Time, stop <-chan os.Signal) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			pm.GatewayUptime.Set(time.Since(startTime).Seconds())
		case <-stop:
			return
		}
	}
}
