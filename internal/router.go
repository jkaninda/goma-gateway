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
	AddRoutes(router2 Router)
	Mux() http.Handler
	UpdateHandler(Gateway)
	ServeHTTP(http.ResponseWriter, *http.Request)
}

type router struct {
	mux           *mux.Router
	enableMetrics bool
	sync.RWMutex
}

// NewRouter creates a new router instance.
func (gateway Gateway) NewRouter() Router {
	rt := &router{
		mux:           mux.NewRouter().StrictSlash(gateway.EnableStrictSlash),
		enableMetrics: gateway.EnableMetrics,
	}
	gateway.addGlobalHandler(rt.mux)
	return rt
}

// AddRoutes adds multiple routes from another router.
func (r *router) AddRoutes(rt Router) {
	for _, route := range dynamicRoutes {
		rt.AddRoute(route)
	}
}

// ServeHTTP handles incoming HTTP requests.
func (r *router) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	r.RLock()
	defer r.RUnlock()
	r.mux.ServeHTTP(writer, request)
}

// UpdateHandler updates the router's handler based on the gateway configuration.
func (r *router) UpdateHandler(gateway Gateway) {
	r.mux = mux.NewRouter().StrictSlash(gateway.EnableStrictSlash)
	gateway.addGlobalHandler(r.mux)
	r.AddRoutes(r)
	logger.Info("Configuration reloaded")
}

// AddRoute adds a single route to the router.
func (r *router) AddRoute(route Route) {
	r.Lock()
	defer r.Unlock()

	if len(route.Path) == 0 {
		logger.Error("Error, path is empty in route %s", route.Name)
		logger.Error("Route path ignored: %s", route.Path)
		return
	}

	rRouter := r.mux.PathPrefix(route.Path).Subrouter()
	if route.DisableHostForwarding {
		logger.Info("Route %s: host forwarding disabled", route.Name)
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
	rRouter.Use(CORSHandler(route.Cors))

	if r.enableMetrics {
		pr := metrics.PrometheusRoute{
			Name: route.Name,
			Path: route.Path,
		}
		rRouter.Use(pr.PrometheusMiddleware)
	}

	proxyHandler := ProxyHandlerErrorInterceptor{
		Enabled:     route.ErrorInterceptor.Enabled,
		ContentType: route.ErrorInterceptor.ContentType,
		Errors:      route.ErrorInterceptor.Errors,
		Origins:     route.Cors.Origins,
	}
	rRouter.Use(proxyHandler.proxyHandler)

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
}

// Mux returns the underlying mux router.
func (r *router) Mux() http.Handler {
	return r.mux
}

// addGlobalHandler configures global handlers and middlewares for the router.
func (gateway Gateway) addGlobalHandler(mux *mux.Router) {
	heath := HealthCheckRoute{
		DisableRouteHealthCheckError: gateway.DisableRouteHealthCheckError,
		Routes:                       dynamicRoutes,
	}

	if gateway.EnableMetrics {
		logger.Info("Metrics enabled")
		mux.Path("/metrics").Handler(promhttp.Handler())
	}

	if !gateway.DisableHealthCheckStatus {
		mux.HandleFunc("/health/routes", heath.HealthCheckHandler).Methods("GET") // Deprecated
		mux.HandleFunc("/healthz/routes", heath.HealthCheckHandler).Methods("GET")
	}

	mux.HandleFunc("/health/live", heath.HealthReadyHandler).Methods("GET") // Deprecated
	mux.HandleFunc("/readyz", heath.HealthReadyHandler).Methods("GET")
	mux.HandleFunc("/healthz", heath.HealthReadyHandler).Methods("GET")

	if gateway.BlockCommonExploits {
		logger.Info("Block common exploits enabled")
		mux.Use(middlewares.BlockExploitsMiddleware)
	}

	if gateway.RateLimit > 0 {
		rLimit := middlewares.RateLimit{
			Id:         "global_rate",
			Unit:       "minute",
			Requests:   gateway.RateLimit,
			Origins:    gateway.Cors.Origins,
			Hosts:      []string{},
			RedisBased: redisBased,
		}
		limiter := rLimit.NewRateLimiterWindow()
		mux.Use(limiter.RateLimitMiddleware())
	}

	mux.Use(CORSHandler(gateway.Cors))
}
