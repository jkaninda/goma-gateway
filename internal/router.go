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
	"github.com/jkaninda/goma-gateway/internal/metrics"
	"github.com/jkaninda/goma-gateway/internal/middlewares"
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
	gateway *Gateway
}

// NewRouter creates a new router instance.
func (g *Gateway) NewRouter() Router {
	rt := &router{
		mux:           mux.NewRouter().StrictSlash(g.EnableStrictSlash),
		enableMetrics: g.EnableMetrics,
		gateway:       g,
	}

	if err := g.addGlobalHandler(rt.mux); err != nil {
		logger.Error("Failed to add global handler", "error", err)
		return nil
	}

	return rt
}

// AddRoutes adds multiple routes from another router.
func (r *router) AddRoutes() error {
	logger.Debug("=========== Adding routes to the router =========", "routes", len(dynamicRoutes))
	for _, route := range dynamicRoutes {
		logger.Debug("Adding route", "route", route.Name, "path", route.Path, "hosts", route.Hosts)
		if !route.Enabled {
			logger.Debug("Skipping disabled route", "route", route.Name, "path", route.Path)
			logger.Info("Proxies Route is disabled", "route", route.Name, "path", route.Path)
			continue
		}
		err := r.AddRoute(route)
		if err != nil {
			return err
		}
	}
	logger.Debug("Finished adding routes to the router")
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
	err := gateway.addGlobalHandler(r.mux)
	if err != nil {
		return
	}
	err = r.AddRoutes()
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
	// Configure CORS
	if err := r.configureCORS(&route); err != nil {
		return fmt.Errorf("failed to configure CORS: %w", err)
	}

	// Load certificates
	certPool, err := r.loadCertPool(route.Security.TLS.RootCAs)
	if err != nil {
		return fmt.Errorf("failed to load certificate pool: %w", err)
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
	}
	rRouter := r.mux.PathPrefix(route.Path).Subrouter()
	// Configure handlers
	if err = r.configureHandlers(route, rRouter, proxyRoute); err != nil {
		return fmt.Errorf("failed to configure handlers: %w", err)
	}
	// Add middlewares
	if err = r.attachMiddlewares(route, rRouter); err != nil {
		return fmt.Errorf("failed to attach middlewares: %w", err)
	}
	return nil
}

// configureCORS handles CORS configuration with deduplication
func (r *router) configureCORS(route *Route) error {
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

	return nil
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
func (r *router) attachMiddlewares(route Route, rRouter *mux.Router) error {
	// Proxy middleware
	proxyMiddleware := &ProxyMiddleware{
		Name:        route.Name,
		Enabled:     route.ErrorInterceptor.Enabled,
		ContentType: route.ErrorInterceptor.ContentType,
		Errors:      route.ErrorInterceptor.Errors,
		Origins:     route.Cors.Origins,
	}
	rRouter.Use(proxyMiddleware.Wrap)
	// CORS middleware
	rRouter.Use(CORSHandler(route.Cors))

	// Custom middlewares
	attachMiddlewares(route, rRouter)

	// Metrics middleware
	if r.enableMetrics {
		pr := metrics.PrometheusRoute{
			Name: route.Name,
			Path: route.Path,
		}
		rRouter.Use(pr.PrometheusMiddleware)
	}

	return nil
}

// configureHandlers sets up route handlers
func (r *router) configureHandlers(route Route, rRouter *mux.Router, proxyRoute *ProxyRoute) error {
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
	return nil
}

// Mux returns the underlying mux router.
func (r *router) Mux() http.Handler {
	return r.mux
}

// addGlobalHandler configures global handlers with better error handling
func (g *Gateway) addGlobalHandler(mux *mux.Router) error {
	logger.Debug("Adding global handler")

	heath := HealthCheckRoute{
		DisableRouteHealthCheckError: g.DisableRouteHealthCheckError,
		Routes:                       dynamicRoutes,
	}

	// Metrics endpoint
	if g.EnableMetrics {
		logger.Debug("Metrics enabled")
		mux.Path("/metrics").Handler(promhttp.Handler())
	}

	// Health check endpoints
	if !g.DisableHealthCheckStatus {
		mux.HandleFunc("/healthz/routes", heath.HealthCheckHandler).Methods("GET")
	}

	mux.HandleFunc("/readyz", heath.HealthReadyHandler).Methods("GET")
	mux.HandleFunc("/healthz", heath.HealthReadyHandler).Methods("GET")

	// Security middleware
	if g.EnableExploitProtection {
		logger.Debug("Block exploit protection enabled")
		mux.Use(middlewares.BlockExploitsMiddleware)
	}

	// Global CORS
	mux.Use(CORSHandler(g.Cors))

	logger.Debug("Added global handler")
	return nil
}
