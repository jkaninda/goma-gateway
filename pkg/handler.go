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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gorilla/mux"
	goutils "github.com/jkaninda/go-utils"
	"github.com/jkaninda/goma-gateway/pkg/logger"
	"github.com/jkaninda/goma-gateway/pkg/middlewares"
	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

// CORSHandler handles CORS headers for incoming requests
//
// Adds CORS headers to the response dynamically based on the provided headers map[string]string
func CORSHandler(cors Cors) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Set CORS headers from the cors config
			// Update Cors Headers
			for k, v := range cors.Headers {
				w.Header().Set(k, v)
			}
			// Update Origin Cors Headers
			if allowedOrigin(cors.Origins, r.Header.Get("Origin")) {
				// Handle preflight requests (OPTIONS)
				if r.Method == "OPTIONS" {
					w.Header().Set(accessControlAllowOrigin, r.Header.Get("Origin"))
					w.WriteHeader(http.StatusNoContent)
					return
				} else {
					w.Header().Set(accessControlAllowOrigin, r.Header.Get("Origin"))
				}
			}
			// Pass the request to the next handler
			next.ServeHTTP(w, r)
		})
	}
}

// ProxyErrorHandler catches backend errors and returns a custom response
func ProxyErrorHandler(w http.ResponseWriter, r *http.Request, err error) {
	startTime := time.Now()
	contentType := r.Header.Get("Content-Type")
	statusCode := ComputeStatusCode(err)

	// Retrieve the value later in the request lifecycle
	if val := r.Context().Value(requestStartTimerKey); val != nil {
		// Get request start time
		startTime = val.(time.Time)
	}
	formatted := goutils.FormatDuration(time.Since(startTime), 1)
	logger.Error("Proxy error: %v", err)
	logger.Error("method=%s url=%s client_ip=%s status=%d duration=%s user_agent=%s", r.Method, r.URL.Path, getRealIP(r), http.StatusBadGateway, formatted, r.UserAgent())

	middlewares.RespondWithError(w, r, statusCode, fmt.Sprintf("%d %s ", statusCode, http.StatusText(statusCode)), nil, contentType)
}

// HealthCheckHandler handles health check of routes
func (heathRoute HealthCheckRoute) HealthCheckHandler(w http.ResponseWriter, r *http.Request) {
	logger.Info("method=%s url=%s client_ip=%s status=%d user_agent=%s", r.Method, r.URL.Path, getRealIP(r), http.StatusOK, r.UserAgent())
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
				logger.Debug("Route %s is healthy", health.Name)
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
	logger.Info("method=%s url=%s client_ip=%s status=%d user_agent=%s", r.Method, r.URL.Path, getRealIP(r), http.StatusOK, r.UserAgent())
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
func allowedOrigin(origins []string, origin string) bool {
	for _, o := range origins {
		if o == origin {
			return true
		}
		continue
	}
	return false

}

// callbackHandler handles oauth callback
func (oauthRuler *OauthRulerMiddleware) callbackHandler(w http.ResponseWriter, r *http.Request) {
	oauthConfig := oauth2Config(oauthRuler)
	// Verify the state to protect against CSRF
	if r.URL.Query().Get("state") != oauthRuler.State {
		http.Error(w, "Invalid state", http.StatusBadRequest)
		return
	}
	// Exchange the authorization code for an access token
	code := r.URL.Query().Get("code")
	token, err := oauthConfig.Exchange(context.Background(), code)
	if err != nil {
		logger.Error("Failed to exchange token: %v", err.Error())
		http.Error(w, "Failed to exchange token", http.StatusInternalServerError)
		return
	}

	// Get user info from the token
	userInfo, err := oauthRuler.getUserInfo(token)
	if err != nil {
		logger.Error("Error getting user info: %v", err)
		http.Error(w, "Error getting user info: ", http.StatusInternalServerError)
		return
	}
	// Generate JWT with user's email
	jwtToken, err := middlewares.CreateJWT(userInfo.Email, oauthRuler.JWTSecret)
	if err != nil {
		logger.Error("Error creating JWT: %v", err)
		http.Error(w, "Error creating JWT ", http.StatusInternalServerError)
		return
	}
	// Save token to a cookie for simplicity
	http.SetCookie(w, &http.Cookie{
		Name:  "goma.oauth",
		Value: jwtToken,
		Path:  oauthRuler.CookiePath,
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
