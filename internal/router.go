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
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jkaninda/goma-gateway/internal/middlewares"
	"github.com/jkaninda/goma-gateway/pkg/plugins"
	"github.com/jkaninda/goma-gateway/util"
	"github.com/jkaninda/njia"
)

type Router interface {
	AddRoute(route *Route) error
	AddRoutes() error
	UpdateHandler(goma *Goma)
	ServeHTTP(http.ResponseWriter, *http.Request)
	// Stop releases the router's background work. Called on shutdown.
	Stop() error
}

type router struct {
	table              atomic.Pointer[njia.Router]
	enableMetrics      bool
	mu                 sync.Mutex
	gateway            *Gateway
	networking         Networking
	strictSlash        bool
	plugins            map[string]plugins.Middleware
	dynamicRoutes      []Route
	dynamicMiddlewares []Middleware
	visitors           *VisitorTracker
	healthStop         chan struct{}
}

// Stop releases router-owned background work. The visitor tracker records what
// is still queued before returning, so the last few seconds of activity aren't
// lost from a store shared with other replicas.
func (r *router) Stop() error {
	r.mu.Lock()
	stop := r.healthStop
	r.healthStop = nil
	r.mu.Unlock()
	if stop != nil {
		close(stop)
	}
	return r.visitors.Stop() // nil-safe when metrics are disabled
}

// newVisitorTracker builds the gateway's single visitor tracker, backed by Redis
// when one is configured so replicas report one shared number.
func newVisitorTracker(m Monitoring) *VisitorTracker {
	if !m.EnableMetrics {
		return nil
	}
	var store VisitorStore = NewMemoryStore()
	if redisBased && middlewares.RedisClient != nil {
		store = NewRedisStore(middlewares.RedisClient)
	}
	return NewVisitorTracker(Config{
		TTL:             visitorTTL(m.VisitorTTL),
		CleanupInterval: defaultVisitorSweep,
		Store:           store,
	})
}

// visitorTTL resolves monitoring.visitorTTL. A bad value warns and falls back
// rather than refusing to start — the gauge is observability, not traffic.
func visitorTTL(raw string) time.Duration {
	if strings.TrimSpace(raw) == "" {
		return defaultVisitorTTL
	}
	d, err := util.ParseDuration(raw)
	if err != nil || d <= 0 {
		logger.Error("Invalid monitoring.visitorTTL, using the default",
			"value", raw, "default", defaultVisitorTTL)
		return defaultVisitorTTL
	}
	// Below the sweep interval the gauge would mostly read zero between
	// republishes, which looks like an outage rather than a short window.
	if d < minVisitorTTL {
		logger.Warn("monitoring.visitorTTL is below the minimum, clamping",
			"value", raw, "minimum", minVisitorTTL)
		return minVisitorTTL
	}
	return d
}

// AddRoutes adds the router's configured routes to its live routing table.
func (r *router) AddRoutes() error {
	return r.addRoutesTo(r.table.Load(), r.dynamicRoutes, r.dynamicMiddlewares, r.plugins)
}

// addRoutesTo compiles a set of routes onto the given table. It takes the table
// and the configuration explicitly so a reload can build a complete table
// off to the side and publish it in one assignment.
func (r *router) addRoutesTo(rt *njia.Router, routes []Route, mids []Middleware, plugs map[string]plugins.Middleware) error {
	logger.Debug("Adding routes to router", "count", len(routes))

	var addedCount int
	var errors []error

	for _, route := range routes {
		if !route.Enabled {
			logger.Debug("Skipping disabled route", "route", route.Name, "path", route.Path)
			continue
		}

		if err := r.addRouteTo(rt, &route, mids, plugs); err != nil {
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
	startTime := time.Now()
	requestID := getRequestID(req)

	ctx := context.WithValue(req.Context(), CtxRequestStartTime, startTime)
	ctx = context.WithValue(ctx, CtxRequestIDHeader, requestID)
	req = req.WithContext(ctx)

	table := r.table.Load()
	if table == nil {
		// Only reachable before the first table is published.
		logger.Error("No routing table is published yet", "path", req.URL.Path)
		http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
		return
	}
	table.ServeHTTP(w, req)
}

// setTable publishes the first routing table.
func (r *router) setTable(table *njia.Router) {
	r.table.Store(table)
}

// swapTable publishes a new routing table in one atomic write. In-flight
// requests finish against the table they started on.
func (r *router) swapTable(table *njia.Router) {
	r.table.Store(table)
}

// UpdateHandler updates the router's handler based on the gateway configuration.
//
// The new table is compiled off to the side and published in a single
// assignment under the write lock. Mutating the live table in place meant
// in-flight requests could hit an empty table, or reach a route whose
// middleware had not been attached yet — unauthenticated, for the length of the
// rebuild.
func (r *router) UpdateHandler(g *Goma) {
	logger.Debug("Updating handler", "routes", len(g.dynamicRoutes))

	next := newProxyRouter(r.strictSlash)
	g.addGlobalHandler(next, r)

	if err := r.addRoutesTo(next, g.dynamicRoutes, g.dynamicMiddlewares, g.plugins); err != nil {
		logger.Error("Failed to add routes, keeping the previous configuration", "error", err)
		return
	}

	// Only now that the new table is known-good is anything swapped, so a
	// rejected reload leaves the gateway serving exactly what it served before.
	stop := make(chan struct{})

	r.mu.Lock()
	previousStop := r.healthStop
	r.healthStop = stop
	r.dynamicRoutes = g.dynamicRoutes
	r.dynamicMiddlewares = g.dynamicMiddlewares
	r.plugins = g.plugins
	routes := r.dynamicRoutes
	r.mu.Unlock()

	r.swapTable(next)

	if previousStop != nil {
		close(previousStop)
	}
	reloaded = true

	logger.Debug("Starting health check...")
	routesHealthCheck(routes, stop)

	// Flush the local DNS cache after a successful reload when enabled, so that
	// updated routes resolve their backends afresh.
	if g.gateway.Networking.DNSCache.ClearOnReload {
		cachedDialer.ClearCache()
		logger.Debug("DNS cache cleared after reload")
	}
	logger.Info("Configuration successfully reloaded", "routes", len(routes))
}

// validateRoute performs comprehensive route validation
func (r *router) validateRoute(route *Route) error {
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

// AddRoute adds a single route to the router's live routing table.
func (r *router) AddRoute(route *Route) error {
	return r.addRouteTo(r.table.Load(), route, r.dynamicMiddlewares, r.plugins)
}

func (r *router) addRouteTo(rt *njia.Router, route *Route, mids []Middleware, plugs map[string]plugins.Middleware) error {
	if err := r.validateRoute(route); err != nil {
		return fmt.Errorf("route validation failed: %w", err)
	}
	// Configure CORS
	r.configureCORS(route)
	var clientCerts []tls.Certificate
	// Load certificates
	clientCert, certPool, err := route.initMTLS()
	if err != nil {
		logger.Error("Failed to load client certificates", "error", err)
	} else {
		if clientCert != nil {
			clientCerts = append(clientCerts, *clientCert)
		}
	}

	// Create proxy route
	proxyRoute := &ProxyRoute{
		name:          route.Name,
		path:          route.Path,
		rewrite:       route.Rewrite,
		target:        route.Target,
		backends:      route.Backends,
		weightedBased: route.Backends.HasPositiveWeight(),
		canaryBased:   route.Backends.IsCanaryBased(),
		methods:       route.Methods,
		hasHeathCheck: len(route.HealthCheck.Path) > 0,
		cors:          route.Cors,
		security:      route.Security,
		clientCerts:   clientCerts,
		certPool:      certPool,
		networking:    r.networking,
	}

	group := rt.Group(groupPrefix(route.Path))
	if route.Maintenance.Enabled {
		logger.Warn("Route maintenance mode enabled", "route", route.Name)
		group.Use(route.Maintenance.MaintenanceMode)
	}

	r.attachMiddlewares(route, group, mids, plugs)
	proxyRoute.responseHeaders = route.responseHeaders
	// Configure handlers
	return r.configureHandlers(route, group, proxyRoute)
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

// attachMiddlewares configures all middlewares for a route
func (r *router) attachMiddlewares(route *Route, rRouter *njia.Group, globalMiddlewares []Middleware, plugs map[string]plugins.Middleware) {
	enableMetrics := r.enableMetrics && !route.DisableMetrics

	if r.enableMetrics && route.DisableMetrics {
		logger.Debug("Metrics collection disabled for route", "route", route.Name)
	}

	var visitorTracker *VisitorTracker
	if enableMetrics {
		visitorTracker = r.visitors
	}
	logger.Debug("Attaching middleware", "route", route.Name, "responseHeaders", len(route.responseHeaders))
	// Proxy middleware
	proxyMiddleware := &ProxyMiddleware{
		Name:           route.Name,
		Path:           route.Path,
		enableMetrics:  enableMetrics,
		Enabled:        route.ErrorInterceptor.Enabled,
		ContentType:    route.ErrorInterceptor.ContentType,
		Errors:         route.ErrorInterceptor.Errors,
		Origins:        route.Cors.Origins,
		VisitorTracker: visitorTracker,
	}
	rRouter.Use(proxyMiddleware.Wrap)
	// Deprecated CORS middleware
	if route.Cors.Enabled {
		cors := &route.Cors
		// CORS middleware
		rRouter.Use(cors.CORSHandler())
	}
	// Custom middlewares
	route.attachMiddlewares(rRouter, globalMiddlewares, plugs)

	// Update proxyMiddleware
	proxyMiddleware.headers = route.responseHeaders
	proxyMiddleware.logRule = route.logRule
	if route.errorInterceptor != nil {
		proxyMiddleware.Enabled = route.errorInterceptor.Enabled
		proxyMiddleware.ContentType = route.errorInterceptor.ContentType
		proxyMiddleware.Errors = route.errorInterceptor.Errors
	}

}

// attachMiddlewares attaches middlewares to the route
func (r *Route) attachMiddlewares(router *njia.Group, globalMiddlewares []Middleware, plugins map[string]plugins.Middleware) {
	if r.Security.EnableExploitProtection {
		logger.Debug("Block common exploits enabled")
		router.Use(middlewares.BlockExploitsMiddleware)
	}

	for _, middleware := range r.Middlewares {
		if len(middleware) == 0 {
			continue
		}
		// Attempt to get middleware from plugins
		if m, exists := plugins[middleware]; exists {
			router.Use(m.Handler)
			continue
		}
		// Attempt to get middleware from global middlewares
		mid, err := getMiddleware([]string{middleware}, globalMiddlewares)
		if err != nil {
			logger.Error("Error validating middleware", "error", err)
			continue
		}

		// Apply middlewares by type
		r.applyMiddlewareByType(mid, router)
	}
}

// configureHandlers registers the route's proxy handler for its path and every
// path beneath it.
func (r *router) configureHandlers(route *Route, group *njia.Group, proxyRoute *ProxyRoute) error {
	var opts []njia.RouteOption
	if route.Priority != 0 {
		opts = append(opts, njia.WithPriority(route.Priority))
	}
	if hosts := nonEmpty(route.Hosts); len(hosts) > 0 {
		opts = append(opts, njia.WithHost(hosts...))
	}

	return registerPrefix(group, njia.MethodAny, route.Name, proxyRoute.ProxyHandler(), opts...)
}

// nonEmpty drops blank entries, which a configuration file can produce for a
// host list and which would otherwise register an unparseable host pattern.
func nonEmpty(in []string) []string {
	out := in[:0:0]
	for _, s := range in {
		if len(s) > 0 {
			out = append(out, s)
		}
	}
	return out
}
