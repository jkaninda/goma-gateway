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
	"github.com/gorilla/mux"
	"github.com/jkaninda/goma-gateway/internal/metrics"
	"github.com/jkaninda/goma-gateway/internal/middlewares"
	"github.com/jkaninda/goma-gateway/pkg/logger"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"net/http"
	"sync"
)

type Router interface {
	AddRoute(route Route)
	Mux() http.Handler
	UpdateHandler(http.Handler)
	ServeHTTP(http.ResponseWriter, *http.Request)
}

type router struct {
	mux           *mux.Router
	enableMetrics bool
	sync.RWMutex
}

func (r *router) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	r.RLock()
	defer r.RUnlock()
	r.mux.ServeHTTP(writer, request)
}

func (r *router) UpdateHandler(handler http.Handler) {
	r.Lock()
	defer r.Unlock()
	r.mux = handler.(*mux.Router)
}

// AddRoute adds a route to the router
func (r *router) AddRoute(route Route) {
	r.Lock()
	defer r.Unlock()
	// create route Router
	rRouter := r.mux.PathPrefix(route.Path).Subrouter()
	if len(route.Path) > 0 {
		if route.DisableHostForwarding {
			logger.Info("Route %s: host forwarding disabled ", route.Name)
		}
		proxyRoute := ProxyRoute{
			path:                  route.Path,
			rewrite:               route.Rewrite,
			destination:           route.Destination,
			backends:              route.Backends,
			methods:               route.Methods,
			disableHostForwarding: route.DisableHostForwarding,
			cors:                  route.Cors,
			insecureSkipVerify:    route.InsecureSkipVerify,
		}
		attachMiddlewares(route, rRouter)

		// Apply route Cors
		rRouter.Use(CORSHandler(route.Cors))
		if r.enableMetrics {
			pr := metrics.PrometheusRoute{
				Name: route.Name,
				Path: route.Path,
			}
			// Prometheus endpoint
			rRouter.Use(pr.PrometheusMiddleware)
		}

		// Apply Proxy Handler
		// Custom error handler for proxy errors
		proxyHandler := ProxyHandlerErrorInterceptor{
			Enabled:     route.ErrorInterceptor.Enabled,
			ContentType: route.ErrorInterceptor.ContentType,
			Errors:      route.ErrorInterceptor.Errors,
			Origins:     route.Cors.Origins,
		}
		rRouter.Use(proxyHandler.proxyHandler)

		// Enable route bot detection
		if route.EnableBotDetection {
			logger.Info("Route %s: Bot detection enabled", route.Name)
			bot := middlewares.BotDetection{}
			rRouter.Use(bot.BotDetectionMiddleware)
		}
		if len(route.Hosts) != 0 {
			for _, host := range route.Hosts {
				rRouter.Host(host).PathPrefix("").Handler(proxyRoute.ProxyHandler())
			}
		} else {
			rRouter.PathPrefix("").Handler(proxyRoute.ProxyHandler())
		}
	} else {
		logger.Error("Error, path is empty in route %s", route.Name)
		logger.Error("Route path ignored: %s", route.Path)
	}
}

// Mux returns the router mux
func (r *router) Mux() http.Handler {
	return r.mux
}

// NewRouter creates a new router
func (gateway Gateway) NewRouter() Router {
	rt := &router{
		mux:           mux.NewRouter().StrictSlash(gateway.EnableStrictSlash),
		enableMetrics: gateway.EnableMetrics,
	}
	r := rt.mux
	heath := HealthCheckRoute{
		DisableRouteHealthCheckError: gateway.DisableRouteHealthCheckError,
		Routes:                       dynamicRoutes,
	}
	if rt.enableMetrics {
		logger.Info("Metrics enabled")
		// Prometheus endpoint
		r.Path("/metrics").Handler(promhttp.Handler())
	}
	// Routes health check
	if !gateway.DisableHealthCheckStatus {
		r.HandleFunc("/health/routes", heath.HealthCheckHandler).Methods("GET") // Deprecated
		r.HandleFunc("/healthz/routes", heath.HealthCheckHandler).Methods("GET")
	}

	// Health check
	r.HandleFunc("/health/live", heath.HealthReadyHandler).Methods("GET") // Deprecated
	r.HandleFunc("/readyz", heath.HealthReadyHandler).Methods("GET")
	r.HandleFunc("/healthz", heath.HealthReadyHandler).Methods("GET")
	// Enable common exploits
	if gateway.BlockCommonExploits {
		logger.Info("Block common exploits enabled")
		r.Use(middlewares.BlockExploitsMiddleware)
	}
	// check if RateLimit is set
	if gateway.RateLimit > 0 {
		// Add rate limit middlewares to all routes, if defined
		rLimit := middlewares.RateLimit{
			Id:         "global_rate",
			Unit:       "minute",
			Requests:   gateway.RateLimit,
			Origins:    gateway.Cors.Origins,
			Hosts:      []string{},
			RedisBased: redisBased,
		}
		limiter := rLimit.NewRateLimiterWindow()
		// Add rate limit middlewares
		r.Use(limiter.RateLimitMiddleware())
	}

	// Apply global Cors middlewares
	r.Use(CORSHandler(gateway.Cors)) // Apply CORS middlewares
	return rt
}
