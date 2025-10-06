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

package pkg

import (
	"github.com/gorilla/mux"
	"github.com/jkaninda/goma-gateway/internal/certmanager"
	"github.com/jkaninda/goma-gateway/pkg/middlewares"
	"sort"
)

// Initialize initializes the routes
func (g *GatewayServer) Initialize() error {
	gateway := g.gateway
	// Handle deprecations
	gateway.handleDeprecations()

	// Load core configuration
	dynamicRoutes = gateway.Routes
	dynamicMiddlewares = g.middlewares

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
			dynamicMiddlewares = append(dynamicMiddlewares, extraMiddlewares...)
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
			dynamicRoutes = append(dynamicRoutes, extraRoutes...)
			logger.Debug("Extra routes loaded", "count", len(extraRoutes))
		}
	}

	// Validate configuration
	logger.Info("Validating configuration", "routes", len(dynamicRoutes), "middlewares", len(dynamicMiddlewares))
	err := validateConfig(dynamicRoutes, dynamicMiddlewares)
	if err != nil {
		logger.Error("Configuration validation failed", "error", err)
		return err
	}
	// Route sorting
	if hasPositivePriority(dynamicRoutes) {
		sort.Slice(dynamicRoutes, func(i, j int) bool {
			return dynamicRoutes[i].Priority < dynamicRoutes[j].Priority
		})
		logger.Debug("Routes sorted by priority")
	} else {
		sort.Slice(dynamicRoutes, func(i, j int) bool {
			return len(dynamicRoutes[i].Path) > len(dynamicRoutes[j].Path)
		})
		logger.Debug("Routes sorted by path length")
	}

	logger.Debug("Validating routes", "count", len(dynamicRoutes))
	dynamicRoutes = validateRoutes(*gateway, dynamicRoutes)

	// Health check
	if !reloaded {
		logger.Debug("Starting background routes healthcheck")
		routesHealthCheck(dynamicRoutes, stopChan)
		logger.Debug("Routes healthcheck running")
	}
	if gateway.Monitoring.EnableMetrics {
		prometheusMetrics.GatewayRoutesCount.Set(float64(len(dynamicRoutes)))
		prometheusMetrics.GatewayMiddlewaresCount.Set(float64(len(dynamicMiddlewares)))
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
		domains := hostNames(dynamicRoutes)
		certManager.UpdateDomains(domains)
		logger.Debug("Updated ACME domains", "count", len(domains))
	}
	debugMode = gateway.Debug
	if len(dynamicRoutes) == 0 {
		logger.Warn("No routes found, add routes to the configuration file")
	}
	return nil
}

// attachMiddlewares attaches middlewares to the route
func attachMiddlewares(route Route, router *mux.Router) {
	if route.Security.EnableExploitProtection {
		logger.Debug("Block common exploits enabled")
		router.Use(middlewares.BlockExploitsMiddleware)
	}

	for _, middleware := range route.Middlewares {
		if len(middleware) == 0 {
			continue
		}

		mid, err := getMiddleware([]string{middleware}, dynamicMiddlewares)
		if err != nil {
			logger.Error("Error validating middleware", "error", err)
			continue
		}

		// Apply middlewares by type
		applyMiddlewareByType(mid, route, router)
	}
}
