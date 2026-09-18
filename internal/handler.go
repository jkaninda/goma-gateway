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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	goutils "github.com/jkaninda/go-utils"
	"github.com/jkaninda/goma-gateway/internal/middlewares"
)

// ProxyErrorHandler catches backend errors and returns a custom response
func ProxyErrorHandler(w http.ResponseWriter, r *http.Request, err error) {
	startTime := time.Now()
	requestID := getRequestID(r)

	contentType := getContentType(r)
	statusCode := ComputeStatusCode(err)

	// Retrieve the value later in the request lifecycle
	if val := r.Context().Value(CtxRequestStartTime); val != nil {
		// Get request start time
		startTime = val.(time.Time)
	}
	if val := r.Context().Value(CtxRequestIDHeader); val != nil {
		requestID = val.(string)
	}

	formatted := goutils.FormatDuration(time.Since(startTime), 1)
	logger.Error("Gateway encountered an error handling request", "error", err)
	logger.Error(
		"Failed to proxy request",
		"method", r.Method,
		"url", r.URL.Path,
		"status", statusCode,
		"host", r.Host,
		"referer", r.Referer(),
		"duration", formatted,
		"client_ip", middlewares.RealIP(r),
		"request_id", requestID,
		"user_agent", r.UserAgent(),
	)
	middlewares.RespondWithError(w, r, statusCode, fmt.Sprintf("%d %s ", statusCode, http.StatusText(statusCode)), nil, contentType)
}

// HealthCheckHandler handles health check of routes
func (heathRoute HealthCheckRoute) HealthCheckHandler(w http.ResponseWriter, r *http.Request) {
	logger.Debug("Route is healthy", "method", r.Method, "url", r.URL.Path, "client_ip", middlewares.RealIP(r), "status", http.StatusOK, "user_agent", r.UserAgent())

	healthRoutes := healthCheckRoutes(heathRoute.Routes)
	wg := sync.WaitGroup{}
	wg.Add(len(healthRoutes))
	var routes []HealthCheckRouteResponse
	for _, health := range healthRoutes {
		go func() {
			err := health.Check()
			if err != nil {
				if heathRoute.DisableRouteHealthCheckError {
					routes = append(routes, HealthCheckRouteResponse{Name: health.Name, Status: "unhealthy", Error: "Route healthcheck errors disabled"})
				} else {
					routes = append(routes, HealthCheckRouteResponse{Name: health.Name, Status: "unhealthy", Error: "Error: " + err.Error()})
				}
			} else {
				logger.Debug("Route healthy", "route", health.Name)
				routes = append(routes, HealthCheckRouteResponse{Name: health.Name, Status: "healthy", Error: ""})
			}
			defer wg.Done()

		}()

	}
	wg.Wait() // Wait for all requests to complete
	response := HealthCheckResponse{
		Status: "healthy", // Goma proxy
		Routes: routes,    // Routes health check
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	err := json.NewEncoder(w).Encode(response)
	if err != nil {
		return
	}
}
func (heathRoute HealthCheckRoute) HealthReadyHandler(w http.ResponseWriter, r *http.Request) {
	logger.Debug("Route is healthy", "method", r.Method, "url", r.URL.Path, "client_ip", middlewares.RealIP(r), "status", http.StatusOK, "user_agent", r.UserAgent())
	response := HealthCheckRouteResponse{
		Name:   "Service Gateway",
		Status: "running",
		Error:  "",
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	err := json.NewEncoder(w).Encode(response)
	if err != nil {
		return
	}
}

// ComputeStatusCode computes the HTTP status code according to the given error.
func ComputeStatusCode(err error) int {
	switch {
	case errors.Is(err, io.EOF):
		return http.StatusBadGateway
	case errors.Is(err, context.Canceled):
		return StatusClientClosedRequest
	case errors.Is(err, http.ErrAbortHandler):
		return http.StatusServiceUnavailable
	default:
		var netErr net.Error
		if errors.As(err, &netErr) {
			if netErr.Timeout() {
				return http.StatusGatewayTimeout
			}

			return http.StatusBadGateway
		}
	}

	return http.StatusInternalServerError
}
