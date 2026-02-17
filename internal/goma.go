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
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"sort"

	"github.com/gorilla/mux"
	goutils "github.com/jkaninda/go-utils"
	"github.com/jkaninda/goma-gateway/internal/middlewares"
	"github.com/jkaninda/goma-gateway/internal/proxy"
	"github.com/jkaninda/goma-gateway/pkg/certmanager"
	"github.com/jkaninda/goma-gateway/pkg/plugins"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Goma struct {
	ctx                   context.Context
	webServer             *http.Server
	webSecureServer       *http.Server
	proxyServer           *proxy.PassThroughServer
	certManager           *certmanager.Config
	configFile            string
	version               string
	gateway               *Gateway
	plugins               map[string]plugins.Middleware
	middlewares           []Middleware
	dynamicMiddlewares    []Middleware
	dynamicRoutes         []Route
	pluginConfig          PluginConfig
	providerManager       *ProviderManager
	tlsCertPool           *x509.CertPool
	tlsClientAuthRequired bool
	tlsConfig             *tls.Config
	defaultCertificate    *tls.Certificate
	extraRouteConfig      ExtraRouteConfig
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

	g.extraRouteConfig.Directory = goutils.Env("GOMA_EXTRA_CONFIG_DIR", gateway.ExtraConfig.Directory)
	g.extraRouteConfig.Watch = goutils.EnvBool("GOMA_EXTRA_CONFIG_WATCH", g.gateway.ExtraConfig.Watch)
	g.gateway.Monitoring.EnableMetrics = goutils.EnvBool("GOMA_ENABLE_METRICS", g.gateway.Monitoring.EnableMetrics)
	// Load Extra Configurations
	if len(g.extraRouteConfig.Directory) > 0 {
		// Load Extra Middlewares
		logger.Debug("Loading extra middlewares", "directory", g.extraRouteConfig.Directory)
		extraMiddlewares, err := loadExtraMiddlewares(g.extraRouteConfig.Directory)
		if err != nil {
			logger.Error("Failed to load extra middlewares", "error", err)
			return err
		}
		if len(extraMiddlewares) > 0 {
			g.dynamicMiddlewares = append(g.dynamicMiddlewares, extraMiddlewares...)
			logger.Debug("Extra middlewares loaded", "count", len(extraMiddlewares))
		}

		// Load Extra Routes
		logger.Debug("Loading extra routes", "directory", g.extraRouteConfig.Directory)
		extraRoutes, err := loadExtraRoutes(g.extraRouteConfig.Directory)
		if err != nil {
			logger.Error("Failed to load extra routes", "error", err)
			return err
		}
		if len(extraRoutes) > 0 {
			g.dynamicRoutes = append(g.dynamicRoutes, extraRoutes...)
			logger.Debug("Extra routes loaded", "count", len(extraRoutes))
		}
	}
	// Check if the provider is set
	if g.providerManager.isConfigured() {
		logger.Debug("Loading configuration from provider", "provider", g.providerManager.activeProvider())
		if g.providerManager.configBundle != nil {
			logger.Debug("Using cached configuration from provider", "provider", g.providerManager.activeProvider())
			g.dynamicRoutes = append(g.dynamicRoutes, g.providerManager.configBundle.Routes...)
			g.dynamicMiddlewares = append(g.dynamicMiddlewares, g.providerManager.configBundle.Middlewares...)
			logger.Debug("Configuration loaded from provider", "routes", len(g.providerManager.configBundle.Routes), "middlewares", len(g.providerManager.configBundle.Middlewares))

		}
	}
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
	// Certificate ProviderManager
	if certManager == nil {
		logger.Debug("Creating certificate providerManager...")
		certManager, err = certmanager.NewCertManager(g.certManager)
		if err != nil {
			logger.Error("Failed to create certificate providerManager", "error", err)
		} else {
			logger.Debug("Certificate providerManager created successfully")
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
	if len(g.gateway.Defaults.Middlewares) == 0 {
		return
	}

	logger.Debug("Applying default middlewares", "count", len(g.gateway.Defaults.Middlewares))

	for i, route := range g.dynamicRoutes {
		logger.Debug("Applying default middlewares", "route", route.Name, "count", len(g.gateway.Defaults.Middlewares))
		existing := make(map[string]struct{})
		for _, m := range route.Middlewares {
			existing[m] = struct{}{}
		}
		final := make([]string, 0, len(g.gateway.Defaults.Middlewares)+len(route.Middlewares))

		for _, m := range g.gateway.Defaults.Middlewares {
			if _, ok := existing[m]; !ok {
				final = append(final, m)
			}
		}
		final = append(final, route.Middlewares...)
		g.dynamicRoutes[i].Middlewares = append([]string(nil), final...)
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
	if goutils.EnvBool("GOMA_ENABLE_READINESS", g.gateway.Monitoring.EnableReadiness) {
		mux.HandleFunc("/readyz", health.HealthReadyHandler).Methods(http.MethodGet)
	}
	if goutils.EnvBool("GOMA_ENABLE_LIVENESS", g.gateway.Monitoring.EnableLiveness) {
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
func (g *Goma) initTlsConfig() error {
	// Configure TLS
	g.tlsConfig = &tls.Config{
		GetCertificate: certManager.GetCertificate,
		NextProtos:     []string{"h2", "http/1.1", "acme-tls/1"},
	}
	if g.tlsCertPool != nil {
		g.tlsConfig.ClientCAs = g.tlsCertPool
		if g.tlsClientAuthRequired {
			g.tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
		} else {
			g.tlsConfig.ClientAuth = tls.VerifyClientCertIfGiven
		}
	}
	if g.defaultCertificate == nil {
		// Generate default certificate
		certificate, err := certManager.GenerateDefaultCertificate()
		if err != nil {
			return err
		}
		g.defaultCertificate = certificate
	}
	// Add default certificate
	certManager.AddCertificate("default", g.defaultCertificate)
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
func (g *Goma) configureProviderManager() error {
	// Initialize Provider ProviderManager
	logger.Debug("Initializing provider providerManager...")
	g.providerManager = newManager()
	// Initialize File Provider
	if g.gateway.Providers.File != nil {
		if g.gateway.Providers.File.Enabled {
			if g.gateway.Providers.File.Directory == "" {
				return fmt.Errorf("file provider directory is required")
			}
			provider, err := NewFileProvider(g.gateway.Providers.File)
			if err != nil {
				return fmt.Errorf("failed to initialize file provider: %w", err)
			}
			if err = g.providerManager.Register(provider); err != nil {
				return fmt.Errorf("failed to register FileProviderType provider: %w", err)
			}
			logger.Debug("File provider initialized")
		}
	}
	// Initialize http provider
	if g.gateway.Providers.HTTP != nil {
		if g.gateway.Providers.HTTP.Enabled {
			provider, err := NewHTTPProvider(g.gateway.Providers.HTTP)
			if err != nil {
				return fmt.Errorf("failed to initialize HTTP provider: %w", err)
			}
			if err = g.providerManager.Register(provider); err != nil {
				return fmt.Errorf("failed to register HTTP provider: %w", err)
			}
			logger.Debug("HTTP provider initialized")
		}
	}
	// Initialize git provider
	if g.gateway.Providers.Git != nil {
		if g.gateway.Providers.Git.Enabled {
			provider, err := NewGitProvider(g.gateway.Providers.Git)
			if err != nil {
				return fmt.Errorf("failed to initialize git provider: %w", err)
			}
			if err = g.providerManager.Register(provider); err != nil {
				return fmt.Errorf("failed to register GitProviderType provider: %w", err)
			}
			logger.Debug("Git provider initialized")
		}

	}
	if g.providerManager.hasActiveProvider() {
		// Initial load
		bundle, err := g.providerManager.Load(g.ctx)
		if err != nil {
			return err
		}
		g.providerManager.configBundle = bundle
	}
	return nil
}
func (g *Goma) watchProvider(r Router) {
	if g.providerManager != nil && g.providerManager.hasActiveProvider() {
		go func() {
			logger.Debug("Starting provider watch", "provider", g.providerManager.activeProvider())
			configCh, err := g.providerManager.Watch(g.ctx)
			if err != nil {
				logger.Error("Failed to watch provider", "error", err)
				return
			}
			for {
				select {
				case <-g.providerManager.stopCh:
					logger.Debug("Stopping provider watch", "provider", g.providerManager.activeProvider())
					return
				case bundle := <-configCh:
					logger.Info("Configuration update received from provider", "provider", g.providerManager.activeProvider())
					g.providerManager.configBundle = bundle
					// Re-initialize routes
					err = g.Initialize()
					if err != nil {
						logger.Error("Failed to re-initialize routes after provider update", "error", err)
						continue
					} else {
						// Update the routes
						logger.Debug("Updating routes")
						r.UpdateHandler(g)
					}
				}
			}
		}()
	}
}

func (g *Goma) stopProviders() error {
	if g.providerManager != nil {
		err := g.providerManager.StopAll()
		if err != nil {
			return fmt.Errorf("failed to stop providers: %w", err)
		}
	}
	return nil
}
