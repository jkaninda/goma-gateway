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
	"github.com/jkaninda/goma-gateway/pkg/logger"
	"github.com/jkaninda/goma-gateway/pkg/metrics"
	"github.com/jkaninda/goma-gateway/pkg/middlewares"
	"github.com/jkaninda/goma-gateway/util"
	"github.com/prometheus/client_golang/prometheus"
	"sort"
)

// init initializes prometheus metrics
func init() {
	_ = prometheus.Register(metrics.TotalRequests)
	_ = prometheus.Register(metrics.ResponseStatus)
	_ = prometheus.Register(metrics.HttpDuration)
}

// Initialize initializes the routes
func (gatewayServer GatewayServer) Initialize() error {
	gateway := gatewayServer.gateway
	handleGatewayDeprecations(&gateway)
	dynamicRoutes = gateway.Routes
	dynamicMiddlewares = gatewayServer.middlewares
	// Load Extra Middlewares
	extraMiddlewares, err := loadExtraMiddlewares(gateway.ExtraConfig.Directory)
	if err == nil {
		dynamicMiddlewares = append(dynamicMiddlewares, extraMiddlewares...)
		logger.Debug("Loaded %d additional middlewares", len(extraMiddlewares))

	}
	// Load Extra Routes
	extraRoutes, err := loadExtraRoutes(gateway.ExtraConfig.Directory)
	if err == nil {
		dynamicRoutes = append(dynamicRoutes, extraRoutes...)
		logger.Debug("Loaded %d additional routes", len(extraRoutes))

	}
	// Check configs
	err = checkConfig(dynamicRoutes, dynamicMiddlewares)
	if err != nil {
		return err
	}
	if len(gateway.Redis.Addr) > 0 {
		redisBased = true
	}
	if hasPositivePriority(dynamicRoutes) {
		// Sort routes by Priority in ascending order
		sort.Slice(dynamicRoutes, func(i, j int) bool {
			return dynamicRoutes[i].Priority < dynamicRoutes[j].Priority
		})
	} else {
		// Sort routes by path in descending order
		sort.Slice(dynamicRoutes, func(i, j int) bool {
			return len(dynamicRoutes[i].Path) > len(dynamicRoutes[j].Path)
		})
	}
	// Update Routes
	dynamicRoutes = validateRoutes(gateway, dynamicRoutes)

	if !reloaded {
		// Routes background healthcheck
		routesHealthCheck(dynamicRoutes, stopChan)
	}
	return nil
}

// attachMiddlewares attaches middlewares to the route
func attachMiddlewares(route Route, router *mux.Router) {
	if route.BlockCommonExploits {
		logger.Debug("Block common exploits enabled")
		router.Use(middlewares.BlockExploitsMiddleware)
	}
	// Apply route rate limit // Deprecated
	applyRateLimit(route, router)

	for _, middleware := range route.Middlewares {
		if len(middleware) == 0 {
			continue
		}

		mid, err := getMiddleware([]string{middleware}, dynamicMiddlewares)
		if err != nil {
			logger.Error("Error: %v", err.Error())
			continue
		}

		// Apply middlewares by type
		applyMiddlewareByType(mid, route, router)
	}
}

func applyRateLimit(route Route, router *mux.Router) {
	if route.RateLimit == 0 {
		return
	}

	rateLimit := middlewares.RateLimit{
		Unit:       "minute",
		Id:         util.Slug(route.Name),
		Requests:   route.RateLimit,
		Origins:    route.Cors.Origins,
		Hosts:      route.Hosts,
		RedisBased: redisBased,
	}
	limiter := rateLimit.NewRateLimiterWindow()
	router.Use(limiter.RateLimitMiddleware())
}
