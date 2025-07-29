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
	"crypto/x509"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"net/http"
	"sync"
	"time"
)

type Router interface {
	AddRoute(route Route) error
	AddRoutes() error
	Mux() http.Handler
	UpdateHandler(*Gateway)
	ServeHTTP(http.ResponseWriter, *http.Request)
}

type router struct {
	mux           *mux.Router
	enableMetrics bool
	sync.RWMutex
	gateway    *Gateway
	networking Networking
}

// NewRouter creates a new router instance.
func (g *Gateway) NewRouter() Router {
	rt := &router{
		mux:           mux.NewRouter().StrictSlash(g.EnableStrictSlash),
		enableMetrics: g.Monitoring.EnableMetrics,
		gateway:       g,
		networking:    g.Networking,
	}

	g.addGlobalHandler(rt.mux)

	return rt
}

// AddRoutes adds multiple routes from another router.
func (r *router) AddRoutes() error {
	logger.Debug("Adding routes to router", "count", len(dynamicRoutes))

	var addedCount int
	var errors []error

	for _, route := range dynamicRoutes {
		if !route.Enabled {
			logger.Debug("Skipping disabled route", "route", route.Name, "path", route.Path)
			continue
		}

		if err := r.AddRoute(route); err != nil {
			logger.Error("Failed to add route", "route", route.Name, "error", err)
			errors = append(errors, fmt.Errorf("route %s: %w", route.Name, err))
			continue
		}
		addedCount++
	}

	logger.Debug("Finished adding routes", "added", addedCount, "errors", len(errors))

	if len(errors) > 0 {
		return fmt.Errorf("failed to add %d routes: %v", len(errors), errors)
	}

	return nil
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

	err := r.AddRoutes()
	if err != nil {
		logger.Error("Failed to add routes", "error", err)
		return
	}
	r.startHealthCheck()
	logger.Info("Configuration successfully reloaded", "routes", len(dynamicRoutes))
}

// startHealthCheck starts the health check routine
func (r *router) startHealthCheck() {
	stopChan = make(chan struct{})
	logger.Debug("Starting health check...")
	routesHealthCheck(dynamicRoutes, stopChan)
}

// validateRoute performs comprehensive route validation
func (r *router) validateRoute(route Route) error {
	if route.Name == "" {
		return fmt.Errorf("route name cannot be empty")
	}

	if route.Path == "" {
		return fmt.Errorf("route path cannot be empty")
	}

	if route.Target == "" && len(route.Backends) == 0 {
		return fmt.Errorf("route must have either target or backends")
	}

	return nil
}

// AddRoute adds a single route to the router.
func (r *router) AddRoute(route Route) error {
	if err := r.validateRoute(route); err != nil {
		return fmt.Errorf("route validation failed: %w", err)
	}
	// Configure CORS
	r.configureCORS(&route)

	// Load certificates
	certPool, err := r.loadCertPool(route.Security.TLS.RootCAs)
	if err != nil {
		logger.Error("Failed to load certificate pool", "error", err)
	}
	// Create proxy route
	proxyRoute := &ProxyRoute{
		name:          route.Name,
		path:          route.Path,
		rewrite:       route.Rewrite,
		target:        route.Target,
		backends:      route.Backends,
		weightedBased: route.Backends.HasPositiveWeight(),
		methods:       route.Methods,
		cors:          route.Cors,
		security:      route.Security,
		certPool:      certPool,
		networking:    r.networking,
	}
	rRouter := r.mux.PathPrefix(route.Path).Subrouter()
	// Configure handlers
	r.configureHandlers(route, rRouter, proxyRoute)
	// Add middlewares
	r.attachMiddlewares(route, rRouter)
	return nil
}

// configureCORS handles CORS configuration with deduplication
func (r *router) configureCORS(route *Route) {
	// Add route methods to CORS allowed methods
	methodsSet := make(map[string]bool)

	// Add existing CORS methods
	for _, method := range route.Cors.AllowMethods {
		methodsSet[method] = true
	}

	// Add route methods
	for _, method := range route.Methods {
		methodsSet[method] = true
	}

	// Convert back to slice
	route.Cors.AllowMethods = make([]string, 0, len(methodsSet))
	for method := range methodsSet {
		route.Cors.AllowMethods = append(route.Cors.AllowMethods, method)
	}

}

// loadCertPool loads certificate pool with better error handling
func (r *router) loadCertPool(rootCAs string) (*x509.CertPool, error) {
	if len(rootCAs) == 0 {
		return nil, nil
	}
	certPool, err := loadCertPool(rootCAs)
	if err != nil {
		logger.Error("Error loading certificate pool", "error", err)
		return nil, err
	}
	return certPool, nil
}

// attachMiddlewares configures all middlewares for a route
func (r *router) attachMiddlewares(route Route, rRouter *mux.Router) {
	enableMetrics := r.enableMetrics && !route.DisableMetrics

	if r.enableMetrics && route.DisableMetrics {
		logger.Debug("Metrics collection disabled for route", "route", route.Name)
	}
	// Proxy middleware
	proxyMiddleware := &ProxyMiddleware{
		Name:          route.Name,
		Path:          route.Path,
		enableMetrics: enableMetrics,
		Enabled:       route.ErrorInterceptor.Enabled,
		ContentType:   route.ErrorInterceptor.ContentType,
		Errors:        route.ErrorInterceptor.Errors,
		Origins:       route.Cors.Origins,
	}
	rRouter.Use(proxyMiddleware.Wrap)
	if route.Cors.Enabled {
		cors := &route.Cors
		// CORS middleware
		rRouter.Use(cors.CORSHandler())
	}
	// Custom middlewares
	attachMiddlewares(route, rRouter)
}

// configureHandlers sets up route handlers
func (r *router) configureHandlers(route Route, rRouter *mux.Router, proxyRoute *ProxyRoute) {
	handler := proxyRoute.ProxyHandler()

	if len(route.Hosts) > 0 {
		for _, host := range route.Hosts {
			if len(host) > 0 {
				rRouter.Host(host).PathPrefix("").Handler(handler)
			} else {
				rRouter.PathPrefix("").Handler(handler)
			}
		}
	} else {
		rRouter.PathPrefix("").Handler(handler)
	}
}

// Mux returns the underlying mux router.
func (r *router) Mux() http.Handler {
	return r.mux
}

// addGlobalHandler configures global handlers with better error handling
func (g *Gateway) addGlobalHandler(mux *mux.Router) {
	logger.Debug("Adding global handler")

	health := HealthCheckRoute{
		DisableRouteHealthCheckError: g.Monitoring.IncludeRouteHealthErrors,
		Routes:                       dynamicRoutes,
	}

	// Register global observability endpoints
	g.registerMetricsHandler(mux)
	g.registerRouteHealthHandler(mux, health)

	// Gateway health endpoints
	if g.Monitoring.EnableReadiness {
		mux.HandleFunc("/readyz", health.HealthReadyHandler).Methods(http.MethodGet)
	}
	if g.Monitoring.EnableLiveness {
		mux.HandleFunc("/healthz", health.HealthReadyHandler).Methods(http.MethodGet)
	}

	// Global middleware
	//	mux.Use(CORSHandler(g.Cors))

	logger.Debug("Added global handler")
}

// registerMetricsHandler configures the /metrics endpoint
func (g *Gateway) registerMetricsHandler(mux *mux.Router) {
	if !g.Monitoring.EnableMetrics {
		return
	}

	logger.Debug("Metrics enabled")

	path := "/metrics"
	if g.Monitoring.MetricsPath != "" {
		path = g.Monitoring.MetricsPath
	}

	sub := mux.PathPrefix(path).Subrouter()
	if g.Monitoring.Host != "" {
		sub.Host(g.Monitoring.Host).PathPrefix("").Handler(promhttp.Handler()).Methods(http.MethodGet)
	} else {
		sub.PathPrefix("").Handler(promhttp.Handler()).Methods(http.MethodGet)
	}
	if middlewares := g.Monitoring.Middleware.Metrics; len(middlewares) > 0 {
		route := Route{
			Path:           path,
			Name:           "metrics",
			Middlewares:    middlewares,
			DisableMetrics: true,
		}
		attachMiddlewares(route, sub)
	}
}

// registerRouteHealthHandler configures the /healthz/routes endpoint
func (g *Gateway) registerRouteHealthHandler(mux *mux.Router, health HealthCheckRoute) {
	if !g.Monitoring.EnableRouteHealthCheck {
		return
	}

	logger.Debug("Route health check enabled")
	path := "/healthz/routes"
	sub := mux.PathPrefix(path).Subrouter()
	if g.Monitoring.Host != "" {
		sub.Host(g.Monitoring.Host).PathPrefix("").HandlerFunc(health.HealthCheckHandler).Methods(http.MethodGet)
	} else {
		sub.PathPrefix("").HandlerFunc(health.HealthCheckHandler).Methods(http.MethodGet)
	}

	if middlewares := g.Monitoring.Middleware.RouteHealthCheck; len(middlewares) > 0 {
		route := Route{
			Path:           path,
			Name:           "routeHealth",
			Middlewares:    middlewares,
			DisableMetrics: true,
		}
		attachMiddlewares(route, sub)
	}
}
