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

package pkg

import (
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"net/http"
	"strconv"
)

type PrometheusRoute struct {
	name string
	path string
}

var totalRequests = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "http_requests_total",
		Help: "Number of get requests.",
	},
	[]string{"path"},
)

var responseStatus = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "response_status",
		Help: "Status of HTTP response",
	},
	[]string{"status"},
)

var httpDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
	Name: "http_response_time_seconds",
	Help: "Duration of HTTP requests.",
}, []string{"path"})

func prometheusMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		route := mux.CurrentRoute(r)
		path, _ := route.GetPathTemplate()
		timer := prometheus.NewTimer(httpDuration.WithLabelValues(path))

		responseStatus.WithLabelValues(strconv.Itoa(http.StatusOK)).Inc()
		totalRequests.WithLabelValues(path).Inc()

		timer.ObserveDuration()
		next.ServeHTTP(w, r)
	})

}
