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
	"github.com/gorilla/mux"
	goutils "github.com/jkaninda/go-utils"
	"github.com/jkaninda/goma-gateway/internal/middlewares"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// CORSHandler creates a middleware function that handles CORS headers for incoming requests
// It dynamically adds CORS headers to responses based on the provided Cors configuration
//
// Parameters:
//   - cors: Cors configuration containing all CORS settings
//
// Returns:
//   - mux.MiddlewareFunc: A middleware function that can be used with gorilla/mux router
func CORSHandler(cors Cors) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get the origin from the request headers
			origin := r.Header.Get("Origin")

			// Skip CORS handling if the origin is not allowed
			if !allowedOrigin(cors.Origins, origin) {
				next.ServeHTTP(w, r)
				return // Important to return here to prevent further processing
			}

			h := w.Header()

			// Always set the allowed origin (either the specific origin or *)
			h.Set(AccessControlAllowOrigin, origin)

			// Set custom headers from the configuration
			for k, v := range cors.Headers {
				if _, ok := h[AccessControlAllowOrigin]; !ok {
					w.Header().Set(k, v)
				}
			}

			// Set allow credentials header if configured
			if cors.AllowCredentials {
				h.Set(AccessControlAllowCredentials, "true")
			}

			// Handle allowed headers
			if len(cors.AllowedHeaders) > 0 {
				// Use configured allowed headers if specified
				h.Set(AccessControlAllowHeaders, strings.Join(cors.AllowedHeaders, ", "))
			} else if reqHeaders := r.Header.Get("Access-Control-Request-Headers"); reqHeaders != "" {
				// Fall back to request headers if no configuration provided
				h.Set(AccessControlAllowHeaders, reqHeaders)
			}

			// Handle allowed methods
			if len(cors.AllowMethods) > 0 {
				// Use configured allowed methods if specified
				h.Set(AccessControlAllowMethods, strings.Join(cors.AllowMethods, ", "))
			} else if reqMethod := r.Header.Get("Access-Control-Request-Method"); reqMethod != "" {
				// Fall back to request method if no configuration provided
				h.Set(AccessControlAllowMethods, reqMethod)
			}

			// Set exposed headers if configured
			if len(cors.ExposeHeaders) > 0 {
				h.Set(AccessControlExposeHeaders, strings.Join(cors.ExposeHeaders, ", "))
			}

			// Set max age for preflight cache if configured
			if cors.MaxAge > 0 {
				h.Set(AccessControlMaxAge, strconv.Itoa(cors.MaxAge))
			}

			// Handle preflight (OPTIONS) requests
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return // End the request for OPTIONS
			}

			// Continue to the next handler for non-OPTIONS requests
			next.ServeHTTP(w, r)
		})
	}
}

// ProxyErrorHandler catches backend errors and returns a custom response
func ProxyErrorHandler(w http.ResponseWriter, r *http.Request, err error) {
	startTime := time.Now()
	requestID := getRequestID(r)

	contentType := r.Header.Get("Content-Type")
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
		"client_ip", getRealIP(r),
		"request_id", requestID,
		"user_agent", r.UserAgent(),
	)
	middlewares.RespondWithError(w, r, statusCode, fmt.Sprintf("%d %s ", statusCode, http.StatusText(statusCode)), nil, contentType)
}

// HealthCheckHandler handles health check of routes
func (heathRoute HealthCheckRoute) HealthCheckHandler(w http.ResponseWriter, r *http.Request) {
	logger.Debug("Route is healthy", "method", r.Method, "url", r.URL.Path, "client_ip", getRealIP(r), "status", http.StatusOK, "user_agent", r.UserAgent())

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
	logger.Debug("Route is healthy", "method", r.Method, "url", r.URL.Path, "client_ip", getRealIP(r), "status", http.StatusOK, "user_agent", r.UserAgent())
	response := HealthCheckRouteResponse{
		Name:   "Service Gateway",
		Status: "healthy",
		Error:  "",
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	err := json.NewEncoder(w).Encode(response)
	if err != nil {
		return
	}
}

// callbackHandler handles oauth callback
func (oauthRuler *OauthRulerMiddleware) callbackHandler(w http.ResponseWriter, r *http.Request) {
	oauthConfig := oauth2Config(oauthRuler)
	// Verify the state to protect against CSRF
	if r.URL.Query().Get("state") != oauthRuler.State {
		http.Error(w, "Invalid state", http.StatusBadRequest)
		return
	}
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "Missing code", http.StatusBadRequest)
		return
	}
	// Exchange the authorization code for an access token
	token, err := oauthConfig.Exchange(context.Background(), code)
	if err != nil {
		logger.Error("Failed to exchange token", "error", err)
		http.Error(w, "Failed to exchange token", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     GomaAccessToken,
		Value:    token.AccessToken,
		Path:     oauthRuler.CookiePath,
		HttpOnly: true,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     GomaRefreshToken,
		Value:    token.RefreshToken,
		Path:     oauthRuler.CookiePath,
		HttpOnly: true,
	})

	// Redirect to the home page or another protected route
	http.Redirect(w, r, oauthRuler.RedirectPath, http.StatusSeeOther)
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
