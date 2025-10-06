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
	"fmt"
	"github.com/jkaninda/goma-gateway/util"
	"gopkg.in/yaml.v3"
	"os"
	"slices"
)

// CheckConfig checks configs
func CheckConfig(fileName string) error {
	if !util.FileExists(fileName) {
		return fmt.Errorf("config file not found: %s", fileName)
	}
	buf, err := os.ReadFile(fileName)
	if err != nil {
		return err
	}
	c := &GatewayConfig{}
	err = yaml.Unmarshal(buf, c)
	if err != nil {
		return fmt.Errorf("parsing the configuration file %q: %w", fileName, err)
	}
	gateway := &GatewayServer{
		ctx:         nil,
		version:     c.Version,
		gateway:     &c.GatewayConfig,
		middlewares: c.Middlewares,
	}
	// Check middlewares
	fmt.Println("Checking middlewares...")
	for index, mid := range c.Middlewares {
		if len(mid.Name) == 0 {
			fmt.Printf("Warning: Middleware name required: index: [%d]\n", index)
		}
		if util.HasWhitespace(mid.Name) {
			fmt.Printf("Warning: Middleware contains whitespace: %s | index: [%d], please remove whitespace characters\n", mid.Name, index)
		}
	}
	fmt.Println("Checking middlewares...done")
	// Check additional routes
	fmt.Println("Checking routes...")
	// Check routes
	checkRoutes(gateway.gateway.Routes, gateway.middlewares)
	fmt.Println("Checking routes...done")

	fmt.Printf("Routes count=%d Middlewares count=%d\n", len(gateway.gateway.Routes), len(gateway.middlewares))

	return nil

}

// checkRoutes checks routes
func checkRoutes(routes []Route, middlewares []Middleware) {
	midNames := middlewareNames(middlewares)
	for index, route := range routes {
		if len(route.Name) == 0 {
			fmt.Printf("Warning: route name is empty, index: [%d]\n", index)
		}
		if route.Destination == "" && route.Target == "" && len(route.Backends) == 0 {
			fmt.Printf("Error: no target or backends specified for route: %s | index: [%d] \n", route.Name, index)
		}
		// checking middleware applied to routes
		for _, middleware := range route.Middlewares {
			if !slices.Contains(midNames, middleware) {
				fmt.Printf("Couldn't find a middleware with the name: %s | route: %s \n", middleware, route.Name)
			}
		}
	}
	// find duplicated route name
	duplicates := findDuplicateRouteNames(routes)
	if len(duplicates) != 0 {
		for _, duplicate := range duplicates {
			fmt.Printf("Duplicated route name was found: %s \n", duplicate)
		}
	}
}

// validateConfig checks configurations and returns error
func validateConfig(routes []Route, middlewares []Middleware) error {
	logger.Debug("Validating configurations...")
	midNames := middlewareNames(middlewares)
	for _, route := range routes {
		if len(route.Name) == 0 {
			target := route.Target
			if target == "" {
				if len(route.Backends) > 0 {
					target = route.Backends[0].Endpoint
				}
			}
			return fmt.Errorf("route name is empty, route with target: %s", target)
		}
		if route.Path == "" {
			return fmt.Errorf("route [%s] has an empty path", route.Name)
		}
		if route.Destination == "" && route.Target == "" && len(route.Backends) == 0 {
			return fmt.Errorf("no target or backends specified for route: %s ", route.Name)
		}
		if len(route.Target) > 0 {
			if err := util.ValidateEndpoint(route.Target); err != nil {
				return fmt.Errorf("route [%s] has an invalid target endpoint: %s, error: %w", route.Name, route.Target, err)
			}
		}
		// Validate backends
		if len(route.Backends) > 0 {
			for _, backend := range route.Backends {
				if len(backend.Endpoint) > 0 {
					if err := util.ValidateEndpoint(backend.Endpoint); err != nil {
						return fmt.Errorf("route [%s] has an invalid backend  endpoint: %s, error: %w", route.Name, backend.Endpoint, err)

					}
				}
			}
		}
		// checking middleware applied to routes
		for _, middleware := range route.Middlewares {
			if !slices.Contains(midNames, middleware) {
				logger.Warn("Couldn't find a middleware with the name", "name", middleware, "route", route.Name)
			}
		}
	}

	// find duplicated middleware name
	duplicates, err := findDuplicateMiddlewareNames(middlewares)
	if err != nil {
		return fmt.Errorf("middlewre %v", err)
	}
	if len(duplicates) != 0 {
		for _, duplicate := range duplicates {
			return fmt.Errorf("duplicated middleware name: %s, the name of the middleware should be unique", duplicate)
		}
	}
	// find duplicated route name
	duplicates = findDuplicateRouteNames(routes)
	if len(duplicates) != 0 {
		for _, duplicate := range duplicates {
			return fmt.Errorf("duplicated route name: %s, the name of the route should be unique", duplicate)

		}
	}
	return nil
}

// middlewareNames reruns middleware names
func middlewareNames(middlewares []Middleware) []string {
	names := []string{}
	for _, mid := range middlewares {
		names = append(names, mid.Name)

	}
	return names
}
