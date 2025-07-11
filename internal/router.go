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
func (g *Gateway) NewRouter() Router {
	rt := &router{
		mux:           mux.NewRouter().StrictSlash(g.EnableStrictSlash),
		enableMetrics: g.EnableMetrics,
	}
	g.addGlobalHandler(rt.mux)
	return rt
}

// AddRoutes adds multiple routes from another router.
func (r *router) AddRoutes(rt Router) {
	logger.Debug("=========== Adding routes to the router =========", "routes", len(dynamicRoutes))
	for _, route := range dynamicRoutes {
		logger.Debug("Adding route", "route", route.Name, "path", route.Path, "hosts", route.Hosts)
		if !route.Enabled {
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
func (r *router) UpdateHandler(gateway *Gateway) {

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
	// Add route methods to Cors Allowed methods
	route.Cors.AllowMethods = append(route.Cors.AllowMethods, route.Methods...)
	// Remove duplicated methods
	route.Cors.AllowMethods = util.RemoveDuplicates(route.Cors.AllowMethods)
	certPool, err := loadCertPool(route.Security.TLS.RootCAs)
	if err != nil {
		logger.Error("Error loading certificate pool", "error", err)
	}
	proxyRoute := ProxyRoute{
		name:          route.Name,
		path:          route.Path,
		rewrite:       route.Rewrite,
		target:        route.Target,
		backends:      route.Backends,
		weightedBased: route.Backends.HasPositiveWeight(),
		methods:       route.Methods,
		//	disableHostForwarding: route.DisableHostForwarding,
		cors: route.Cors,
		//	insecureSkipVerify:    route.InsecureSkipVerify,
		security: route.Security,
		certPool: certPool,
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

	proxyHandler := &ProxyHandler{
		Name:        route.Name,
		Enabled:     route.ErrorInterceptor.Enabled,
		ContentType: route.ErrorInterceptor.ContentType,
		Errors:      route.ErrorInterceptor.Errors,
		Origins:     route.Cors.Origins,
	}
	rRouter.Use(proxyHandler.Wrap)

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
func (g *Gateway) addGlobalHandler(mux *mux.Router) {
	logger.Debug("Adding global handler", "routes", len(dynamicRoutes))
	heath := HealthCheckRoute{
		DisableRouteHealthCheckError: g.DisableRouteHealthCheckError,
		Routes:                       dynamicRoutes,
	}

	if g.EnableMetrics {
		logger.Debug("Metrics enabled")
		mux.Path("/metrics").Handler(promhttp.Handler())
	}

	if !g.DisableHealthCheckStatus {
		mux.HandleFunc("/healthz/routes", heath.HealthCheckHandler).Methods("GET")
	}

	mux.HandleFunc("/readyz", heath.HealthReadyHandler).Methods("GET")
	mux.HandleFunc("/healthz", heath.HealthReadyHandler).Methods("GET")

	if g.EnableExploitProtection {
		logger.Debug("Block exploit protection enabled")
		mux.Use(middlewares.BlockExploitsMiddleware)
	}

	mux.Use(CORSHandler(g.Cors))
	logger.Debug("Added global handler", "routes", len(dynamicRoutes))
}
