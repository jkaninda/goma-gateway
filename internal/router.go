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
	"github.com/gorilla/mux"
	"github.com/jkaninda/goma-gateway/internal/metrics"
	"github.com/jkaninda/goma-gateway/internal/middlewares"
	"github.com/jkaninda/goma-gateway/util"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"net/http"
	"time"
)

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
	logger.Debug("=========== Adding routes to the router =========", "routes", len(dynamicRoutes))
	for _, route := range dynamicRoutes {
		logger.Debug("Adding route", "route", route.Name, "path", route.Path, "hosts", route.Hosts)
		if route.Disabled {
			logger.Debug("Skipping disabled route", "route", route.Name, "path", route.Path)
			logger.Info("Proxies Route is disabled", "route", route.Name, "path", route.Path)
			continue
		}
		rt.AddRoute(route)
	}
	logger.Debug("Finished adding routes to the router")
}

// ServeHTTP handles incoming HTTP requests.
func (r *router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.RLock()
	defer r.RUnlock()

	startTime := time.Now()
	requestID := getRequestID(req)

	ctx := context.WithValue(req.Context(), CtxRequestStartTime, startTime)
	ctx = context.WithValue(ctx, CtxRequestIDHeader, requestID)

	req = req.WithContext(ctx)
	r.mux.ServeHTTP(w, req)
}

// UpdateHandler updates the router's handler based on the gateway configuration.
func (r *router) UpdateHandler(gateway Gateway) {

	logger.Debug("Updating handler", "routes", len(dynamicRoutes))
	close(stopChan)
	reloaded = true
	logger.Debug("Updating router with new routes")
	r.mux = mux.NewRouter().StrictSlash(gateway.EnableStrictSlash)
	gateway.addGlobalHandler(r.mux)
	r.AddRoutes(r)
	stopChan = make(chan struct{})
	// Routes background healthcheck
	logger.Debug("Adding routes healthcheck...")
	routesHealthCheck(dynamicRoutes, stopChan)
	logger.Info("Configuration successfully reloaded", "routes", len(dynamicRoutes))
}

// AddRoute adds a single route to the router.
func (r *router) AddRoute(route Route) {
	logger.Debug("Adding route", "route", route.Name, "path", route.Path, "hosts", route.Hosts)
	if len(route.Path) == 0 {
		logger.Error("Error, path is empty in route", "route", route.Name)
		logger.Error("Route path ignored", "path", route.Path)
		return
	}

	rRouter := r.mux.PathPrefix(route.Path).Subrouter()
	if route.DisableHostForwarding {
		logger.Debug("Host forwarding disabled", "route", route.Name)
	}
	// Add route methods to Cors Allowed methods
	route.Cors.AllowMethods = append(route.Cors.AllowMethods, route.Methods...)
	// Remove duplicated methods
	route.Cors.AllowMethods = util.RemoveDuplicates(route.Cors.AllowMethods)

	proxyRoute := ProxyRoute{
		name:                  route.Name,
		path:                  route.Path,
		rewrite:               route.Rewrite,
		destination:           route.Destination,
		backends:              route.Backends,
		weightedBased:         route.Backends.HasPositiveWeight(),
		methods:               route.Methods,
		disableHostForwarding: route.DisableHostForwarding,
		cors:                  route.Cors,
		insecureSkipVerify:    route.InsecureSkipVerify,
	}
	rRouter.Use(CORSHandler(route.Cors))
	attachMiddlewares(route, rRouter)

	if r.enableMetrics {
		pr := metrics.PrometheusRoute{
			Name: route.Name,
			Path: route.Path,
		}
		rRouter.Use(pr.PrometheusMiddleware)
	}

	proxyMiddleware := &ProxyMiddleware{
		Name:        route.Name,
		Enabled:     route.ErrorInterceptor.Enabled,
		ContentType: route.ErrorInterceptor.ContentType,
		Errors:      route.ErrorInterceptor.Errors,
		Origins:     route.Cors.Origins,
	}
	rRouter.Use(proxyMiddleware.Wrap)

	if route.EnableBotDetection {
		logger.Debug("Bot detection enabled", "route", route.Name)
		bot := middlewares.BotDetection{}
		rRouter.Use(bot.BotDetectionMiddleware)
	}

	if len(route.Hosts) > 0 {
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
	logger.Debug("Adding global handler", "routes", len(dynamicRoutes))
	heath := HealthCheckRoute{
		DisableRouteHealthCheckError: gateway.DisableRouteHealthCheckError,
		Routes:                       dynamicRoutes,
	}

	if gateway.EnableMetrics {
		logger.Debug("Metrics enabled")
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
		logger.Debug("Block common exploits enabled")
		mux.Use(middlewares.BlockExploitsMiddleware)
	}

	if gateway.RateLimit > 0 {
		rLimit := middlewares.RateLimit{
			Id:         "global_rate",
			Unit:       "second",
			Requests:   gateway.RateLimit,
			Origins:    gateway.Cors.Origins,
			Hosts:      []string{},
			RedisBased: redisBased,
		}
		limiter := rLimit.NewRateLimiterWindow()
		mux.Use(limiter.RateLimitMiddleware())
	}
	logger.Debug("Added global handler", "routes", len(dynamicRoutes))
}
