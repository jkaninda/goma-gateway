package pkg

/*
Copyright 2024 Jonas Kaninda

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
import (
	"encoding/json"
	"github.com/gorilla/mux"
	"github.com/jkaninda/goma-gateway/internal/logger"
	"net/http"
)

// CORSHandler handles CORS headers for incoming requests
//
// Adds CORS headers to the response dynamically based on the provided headers map[string]string
func CORSHandler(cors Cors) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Set CORS headers from the cors config
			//Update Cors Headers
			for k, v := range cors.Headers {
				w.Header().Set(k, v)
			}
			//Update Origin Cors Headers
			for _, origin := range cors.Origins {
				if origin == r.Header.Get("Origin") {
					w.Header().Set("Access-Control-Allow-Origin", origin)

				}
			}
			// Handle preflight requests (OPTIONS)
			if r.Method == "OPTIONS" {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			// Pass the request to the next handler
			next.ServeHTTP(w, r)
		})
	}
}

// ProxyErrorHandler catches backend errors and returns a custom response
func ProxyErrorHandler(w http.ResponseWriter, r *http.Request, err error) {
	logger.Error("Proxy error: %v", err)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadGateway)
	err = json.NewEncoder(w).Encode(map[string]interface{}{
		"success": false,
		"code":    http.StatusBadGateway,
		"message": "The service is currently unavailable. Please try again later.",
	})
	if err != nil {
		return
	}
	return
}

// HealthCheckHandler handles health check of routes
func (heathRoute HealthCheckRoute) HealthCheckHandler(w http.ResponseWriter, r *http.Request) {
	logger.Info("%s %s %s %s", r.Method, r.RemoteAddr, r.URL, r.UserAgent())
	var routes []HealthCheckRouteResponse
	for _, route := range heathRoute.Routes {
		if route.HealthCheck != "" {
			err := HealthCheck(route.Destination + route.HealthCheck)
			if err != nil {
				logger.Error("Route %s: %v", route.Name, err)
				if heathRoute.DisableRouteHealthCheckError {
					routes = append(routes, HealthCheckRouteResponse{Name: route.Name, Status: "unhealthy", Error: "Route healthcheck errors disabled"})
					continue
				}
				routes = append(routes, HealthCheckRouteResponse{Name: route.Name, Status: "unhealthy", Error: err.Error()})
				continue
			} else {
				logger.Info("Route %s is healthy", route.Name)
				routes = append(routes, HealthCheckRouteResponse{Name: route.Name, Status: "healthy", Error: ""})
				continue
			}
		} else {
			logger.Error("Route %s's healthCheck is undefined", route.Name)
			routes = append(routes, HealthCheckRouteResponse{Name: route.Name, Status: "undefined", Error: ""})
			continue

		}
	}
	response := HealthCheckResponse{
		Status: "healthy",
		Routes: routes,
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	err := json.NewEncoder(w).Encode(response)
	if err != nil {
		return
	}
}
func (heathRoute HealthCheckRoute) HealthReadyHandler(w http.ResponseWriter, r *http.Request) {
	response := HealthCheckRouteResponse{
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
