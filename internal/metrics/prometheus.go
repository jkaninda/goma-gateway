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

// PrometheusMetrics holds all Prometheus metrics
type PrometheusMetrics struct {
	TotalRequests           *prometheus.CounterVec
	ResponseStatus          *prometheus.CounterVec
	HttpDuration            *prometheus.HistogramVec
	HTTPRequestSize         *prometheus.HistogramVec
	GatewayTotalRequests    *prometheus.CounterVec
	GatewayUptime           prometheus.Gauge
	GatewayRoutesCount      prometheus.Gauge
	GatewayMiddlewaresCount prometheus.Gauge
}

// NewPrometheusMetrics creates a new set of Prometheus metrics
func NewPrometheusMetrics(startTime time.Time, stop chan os.Signal) *PrometheusMetrics {
	gatewayUptime := promauto.NewGauge(prometheus.GaugeOpts{
		Name: "gateway_uptime_seconds",
		Help: "Uptime of the gateway application in seconds",
	})
	pm := &PrometheusMetrics{
		GatewayUptime: gatewayUptime,
		GatewayRoutesCount: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "gateway_routes_count",
			Help: "Current number of routes registered in the gateway",
		}),
		GatewayMiddlewaresCount: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "gateway_middlewares_count",
			Help: "Current number of middlewares registered in the gateway",
		}),
		GatewayTotalRequests: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "gateway_requests_total",
				Help: "Total number of requests handled by the gateway since startup",
			},
			[]string{"name", "path", "method"},
		),
		TotalRequests: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "http_requests_total",
				Help: "Total number of HTTP requests, similar to gateway_requests_total",
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
		HTTPRequestSize: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "http_request_size_bytes",
				Help:    "Size of HTTP requests in bytes",
				Buckets: []float64{100, 500, 1000, 5000, 10000, 50000, 100000, 500000, 1000000},
			},
			[]string{"name", "path", "method"},
		),
	}

	// Start a goroutine to continuously update the gateway uptime
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
