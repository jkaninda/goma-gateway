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
	njia          *njia.Router
	enableMetrics bool
	sync.RWMutex
	gateway            *Gateway
	networking         Networking
	strictSlash        bool
	plugins            map[string]plugins.Middleware
	dynamicRoutes      []Route
	dynamicMiddlewares []Middleware
	// visitors feeds the real-time visitors gauge. Gateway-wide and shared by
	// every route; nil when metrics are disabled.
	visitors *VisitorTracker
}

// Stop releases router-owned background work. The visitor tracker records what
// is still queued before returning, so the last few seconds of activity aren't
// lost from a store shared with other replicas.
func (r *router) Stop() error {
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

// AddRoutes adds multiple routes from another router.
func (r *router) AddRoutes() error {
	logger.Debug("Adding routes to router", "count", len(r.dynamicRoutes))

	var addedCount int
	var errors []error

	for _, route := range r.dynamicRoutes {
		if !route.Enabled {
			logger.Debug("Skipping disabled route", "route", route.Name, "path", route.Path)
			continue
		}

		if err := r.AddRoute(&route); err != nil {
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
	r.njia.ServeHTTP(w, req)
}

// UpdateHandler updates the router's handler based on the gateway configuration.
func (r *router) UpdateHandler(g *Goma) {

	r.dynamicRoutes = g.dynamicRoutes
	r.dynamicMiddlewares = g.dynamicMiddlewares
	r.plugins = g.plugins
	logger.Debug("Updating handler", "routes", len(r.dynamicRoutes))
	close(stopChan)
	reloaded = true
	logger.Debug("Updating router with new routes")
	r.njia = newProxyRouter(r.strictSlash)
	g.addGlobalHandler(r.njia, r)

	err := r.AddRoutes()
	if err != nil {
		logger.Error("Failed to add routes", "error", err)
		return
	}
	r.startHealthCheck()
	// Flush the local DNS cache after a successful reload when enabled, so that
	// updated routes resolve their backends afresh.
	if g.gateway.Networking.DNSCache.ClearOnReload {
		cachedDialer.ClearCache()
		logger.Debug("DNS cache cleared after reload")
	}
	logger.Info("Configuration successfully reloaded", "routes", len(r.dynamicRoutes))
}

// startHealthCheck starts the health check routine
func (r *router) startHealthCheck() {
	stopChan = make(chan struct{})
	logger.Debug("Starting health check...")
	routesHealthCheck(r.dynamicRoutes, stopChan)
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

// AddRoute adds a single route to the router.
func (r *router) AddRoute(route *Route) error {
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
	// The route and everything beneath it live in one group, which is what
	// carries the middleware. njia resolves a group's middleware when the table
	// is compiled, so Use and the registrations below may happen in any order:
	// every route in the group is wrapped either way.
	group := r.njia.Group(groupPrefix(route.Path))
	// Check maintenance mode
	if route.Maintenance.Enabled {
		logger.Warn("Route maintenance mode enabled", "route", route.Name)
		group.Use(route.Maintenance.MaintenanceMode)
	}
	// Add middlewares. Order of the Use calls is what nests them, outermost
	// first, so maintenance mode stays outside everything it short-circuits.
	r.attachMiddlewares(route, group, r.dynamicMiddlewares)
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
func (r *router) attachMiddlewares(route *Route, rRouter *njia.Group, globalMiddlewares []Middleware) {
	enableMetrics := r.enableMetrics && !route.DisableMetrics

	if r.enableMetrics && route.DisableMetrics {
		logger.Debug("Metrics collection disabled for route", "route", route.Name)
	}
	// The visitor tracker is gateway-wide and built once (see newVisitorTracker):
	// the gauge it feeds counts the whole gateway, and building one here would
	// give every route its own count and leak a goroutine on every reload.
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
	route.attachMiddlewares(rRouter, globalMiddlewares, r.plugins)

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
//
// The handler answers every HTTP method: a gateway forwards whatever verb the
// client sent, and which ones a route actually allows is enforced further in,
// against route.Methods, so that a rejected verb gets the gateway's own error
// rather than a bare router 405.
func (r *router) configureHandlers(route *Route, group *njia.Group, proxyRoute *ProxyRoute) error {
	var opts []njia.RouteOption
	// Lower priority wins, which is the order the gateway documents. Left at
	// the default, routes fall back to longest-path-first.
	if route.Priority != 0 {
		opts = append(opts, njia.WithPriority(route.Priority))
	}
	if hosts := nonEmpty(route.Hosts); len(hosts) > 0 {
		opts = append(opts, njia.WithHost(hosts...))
	}

	// The group applies its middleware, so the handler is registered bare. Any
	// route a middleware registered on the group — an OAuth callback, say — is
	// an exact path and outranks this catch-all on specificity.
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
