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
	"errors"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/jkaninda/goma-gateway/internal/middlewares"
	"github.com/jkaninda/goma-gateway/internal/proxy"
	"github.com/jkaninda/goma-gateway/pkg/certmanager"
	"github.com/jkaninda/goma-gateway/pkg/plugins"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"net/http"
	"sort"
)

type Goma struct {
	ctx                context.Context
	webServer          *http.Server
	webSecureServer    *http.Server
	proxyServer        *proxy.PassThroughServer
	certManager        *certmanager.Config
	configFile         string
	version            string
	gateway            *Gateway
	plugins            map[string]plugins.Middleware
	middlewares        []Middleware
	defaults           DefaultConfig
	dynamicMiddlewares []Middleware
	dynamicRoutes      []Route
	pluginConfig       PluginConfig
}

// Initialize initializes the routes
func (g *Goma) Initialize() error {
	gateway := g.gateway
	// Handle deprecations
	gateway.handleDeprecations()

	// Initialize trusted proxies
	g.initTrustedProxyConfig()
	// Load core configuration
	g.dynamicRoutes = gateway.Routes
	g.dynamicMiddlewares = g.middlewares

	// Load Extra Configurations
	if len(gateway.ExtraConfig.Directory) > 0 {
		// Load Extra Middlewares
		logger.Debug("Loading extra middlewares", "directory", gateway.ExtraConfig.Directory)
		extraMiddlewares, err := loadExtraMiddlewares(gateway.ExtraConfig.Directory)
		if err != nil {
			logger.Error("Failed to load extra middlewares", "error", err)
			return err
		}
		if len(extraMiddlewares) > 0 {
			g.dynamicMiddlewares = append(g.dynamicMiddlewares, extraMiddlewares...)
			logger.Debug("Extra middlewares loaded", "count", len(extraMiddlewares))
		}

		// Load Extra Routes
		logger.Debug("Loading extra routes", "directory", gateway.ExtraConfig.Directory)
		extraRoutes, err := loadExtraRoutes(gateway.ExtraConfig.Directory)
		if err != nil {
			logger.Error("Failed to load extra routes", "error", err)
			return err
		}
		if len(extraRoutes) > 0 {
			g.dynamicRoutes = append(g.dynamicRoutes, extraRoutes...)
			logger.Debug("Extra routes loaded", "count", len(extraRoutes))
		}
	}
	g.applyDefaultMiddlewarePaths()
	// Attach default configurations
	g.attachDefaultConfigurations()

	// Validate configuration
	logger.Info("Validating configuration", "routes", len(g.dynamicRoutes), "middlewares", len(g.dynamicMiddlewares))
	err := validateConfig(g.dynamicRoutes, g.dynamicMiddlewares)
	if err != nil {
		logger.Error("Configuration validation failed", "error", err)
		return err
	}
	g.registerPlugins()

	// Route sorting
	if hasPositivePriority(g.dynamicRoutes) {
		sort.Slice(g.dynamicRoutes, func(i, j int) bool {
			return g.dynamicRoutes[i].Priority < g.dynamicRoutes[j].Priority
		})
		logger.Debug("Routes sorted by priority")
	} else {
		sort.Slice(g.dynamicRoutes, func(i, j int) bool {
			return len(g.dynamicRoutes[i].Path) > len(g.dynamicRoutes[j].Path)
		})
		logger.Debug("Routes sorted by path length")
	}

	logger.Debug("Validating routes", "count", len(g.dynamicRoutes))
	g.dynamicRoutes = validateRoutes(*gateway, g.dynamicRoutes)

	// Health check
	if !reloaded {
		logger.Debug("Starting background routes healthcheck")
		routesHealthCheck(g.dynamicRoutes, stopChan)
		logger.Debug("Routes healthcheck running")
	}
	if gateway.Monitoring.EnableMetrics {

		prometheusMetrics.GatewayRoutesCount.Set(float64(len(g.dynamicRoutes)))
		prometheusMetrics.GatewayMiddlewaresCount.Set(float64(len(g.dynamicMiddlewares)))
	}
	// Certificate Manager
	if certManager == nil {
		logger.Debug("Creating certificate manager...")
		certManager, err = certmanager.NewCertManager(g.certManager)
		if err != nil {
			logger.Error("Failed to create certificate manager", "error", err)
		} else {
			logger.Debug("Certificate manager created successfully")
		}
	}
	// TLS certificates
	logger.Debug("Loading TLS certificates...")
	if ok, certs := g.initTLS(); ok {
		certManager.AddCertificates(certs)
		logger.Debug("TLS certificates loaded", "count", len(certs))
	}

	// Domain update for certManager
	if certManager != nil && certManager.AcmeInitialized() {
		domains := hostNames(g.dynamicRoutes)
		certManager.UpdateDomains(domains)
		logger.Debug("Updated ACME domains", "count", len(domains))
	}
	debugMode = gateway.Debug
	if len(g.dynamicRoutes) == 0 {
		logger.Warn("No routes found, add routes to the configuration file")
	}
	return nil
}
func (g *Goma) attachDefaultConfigurations() {
	// Apply default middlewares to the routes
	if len(g.defaults.Middlewares) > 0 {
		logger.Debug("Applying default middlewares", "count", len(g.defaults.Middlewares))
		for i, route := range g.dynamicRoutes {
			logger.Debug("Applying default middlewares", "route", route.Name)
			g.dynamicRoutes[i].Middlewares = append(g.defaults.Middlewares, route.Middlewares...)
		}
	}
}

// NewRouter creates a new router instance.
func (g *Goma) NewRouter() Router {
	rt := &router{
		plugins:            g.plugins,
		mux:                mux.NewRouter().StrictSlash(g.gateway.StrictSlash),
		enableMetrics:      g.gateway.Monitoring.EnableMetrics,
		gateway:            g.gateway,
		networking:         g.gateway.Networking,
		strictSlash:        g.gateway.StrictSlash,
		dynamicRoutes:      g.dynamicRoutes,
		dynamicMiddlewares: g.dynamicMiddlewares,
	}

	g.addGlobalHandler(rt.mux)

	return rt
}

// addGlobalHandler configures global handlers with better error handling
func (g *Goma) addGlobalHandler(mux *mux.Router) {
	logger.Debug("Adding global handler")

	health := HealthCheckRoute{
		DisableRouteHealthCheckError: g.gateway.Monitoring.IncludeRouteHealthErrors,
		Routes:                       g.dynamicRoutes,
	}

	// Register global observability endpoints
	g.registerMetricsHandler(mux)
	g.registerRouteHealthHandler(mux, health)

	// Gateway health endpoints
	if g.gateway.Monitoring.EnableReadiness {
		mux.HandleFunc("/readyz", health.HealthReadyHandler).Methods(http.MethodGet)
	}
	if g.gateway.Monitoring.EnableLiveness {
		mux.HandleFunc("/healthz", health.HealthReadyHandler).Methods(http.MethodGet)
	}
	logger.Debug("Added global handler")
}

// registerMetricsHandler configures the /metrics endpoint
func (g *Goma) registerMetricsHandler(mux *mux.Router) {
	if !g.gateway.Monitoring.EnableMetrics {
		return
	}

	logger.Debug("Metrics enabled")

	path := "/metrics"
	if g.gateway.Monitoring.MetricsPath != "" {
		path = g.gateway.Monitoring.MetricsPath
	}

	sub := mux.PathPrefix(path).Subrouter()
	if g.gateway.Monitoring.Host != "" {
		sub.Host(g.gateway.Monitoring.Host).PathPrefix("").Handler(promhttp.Handler()).Methods(http.MethodGet)
	} else {
		sub.PathPrefix("").Handler(promhttp.Handler()).Methods(http.MethodGet)
	}
	if metricsMiddlewares := g.gateway.Monitoring.Middleware.Metrics; len(metricsMiddlewares) > 0 {
		route := &Route{
			Path:           path,
			Name:           "metrics",
			Middlewares:    metricsMiddlewares,
			DisableMetrics: true,
		}
		route.attachMiddlewares(sub, g.dynamicMiddlewares, g.plugins)
	}
}

// registerRouteHealthHandler configures the /healthz/routes endpoint
func (g *Goma) registerRouteHealthHandler(mux *mux.Router, health HealthCheckRoute) {
	if !g.gateway.Monitoring.EnableRouteHealthCheck {
		return
	}

	logger.Debug("Route health check enabled")
	path := "/healthz/routes"
	sub := mux.PathPrefix(path).Subrouter()
	if g.gateway.Monitoring.Host != "" {
		sub.Host(g.gateway.Monitoring.Host).PathPrefix("").HandlerFunc(health.HealthCheckHandler).Methods(http.MethodGet)
	} else {
		sub.PathPrefix("").HandlerFunc(health.HealthCheckHandler).Methods(http.MethodGet)
	}

	if healthCheckMiddlewares := g.gateway.Monitoring.Middleware.RouteHealthCheck; len(healthCheckMiddlewares) > 0 {
		route := &Route{
			Path:           path,
			Name:           "routeHealth",
			Middlewares:    healthCheckMiddlewares,
			DisableMetrics: true,
		}
		route.attachMiddlewares(sub, g.dynamicMiddlewares, g.plugins)
	}
}

// applyDefaultMiddlewarePaths applies default paths to dynamicMiddlewares without specified paths
func (g *Goma) applyDefaultMiddlewarePaths() {
	// Apply default paths to middlewares if no paths are specified
	for i := range g.dynamicMiddlewares {
		if len(g.dynamicMiddlewares[i].Paths) == 0 {
			// protect all paths by default
			g.dynamicMiddlewares[i].Paths = append(g.dynamicMiddlewares[i].Paths, "/.*")
		}
	}
}
func (g *Goma) loadPlugins() error {
	if len(g.pluginConfig.Path) > 0 {

		// Load plugins
		logger.Debug("Loading plugins...", " path", g.pluginConfig.Path)
		err := middlewares.LoadPluginsFromDir(g.pluginConfig.Path)
		if err != nil {
			return fmt.Errorf("failed to load plugins: %w", err)
		}
		logger.Debug("Plugins loaded")
	}
	return nil
}
func (g *Goma) initTrustedProxyConfig() {
	cfg := g.gateway.Proxy
	if !cfg.Enabled {
		logger.Debug("Proxy configuration disabled")
		return
	}

	// Initialize trusted proxies
	proxyConfig, err := cfg.Init()
	if err != nil {
		logger.Error("Failed to initialize proxy configuration", "error", err)
		return
	}

	middlewares.TrustedProxyConfig = proxyConfig
	logger.Debug("Proxy configuration initialized",
		"trusted_proxies_count", len(cfg.TrustedProxies),
		"ip_headers_count", len(cfg.IPHeaders),
	)
}

func (g *Goma) registerPlugins() {
	if err := g.loadPlugins(); err != nil {
		logger.Error("Failed to load plugins", "error", err)
		return
	}

	logger.Debug("Registering middlewares...")

	for _, m := range g.dynamicMiddlewares {
		mw, err := middlewares.Create(string(m.Type), m.Paths, m.Rule)
		if err != nil {
			if errors.Is(err, middlewares.ErrPluginNotFound) {
				if !doesExist(string(m.Type)) {
					logger.Error("Middleware type not found", "name", m.Name, "type", m.Type)
				}
				continue
			}

			logger.Error("Failed to create middleware plugin", "name", m.Name, "type", m.Type, "error", err)
			continue
		}

		if err := mw.Validate(); err != nil {
			logger.Error("Failed to validate middleware plugin", "name", m.Name, "type", m.Type, "error", err)
			continue
		}

		g.plugins[m.Name] = mw
		logger.Debug("Plugin registered", "name", m.Name, "type", m.Type)
	}

	logger.Debug("Plugins registration completed", "count", len(g.plugins))
}
