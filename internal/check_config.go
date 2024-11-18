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
		gateway:     c.GatewayConfig,
		middlewares: c.Middlewares,
	}
	dynamicRoutes = gateway.gateway.Routes
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
	// Load Extra Routes
	if len(gateway.gateway.ExtraRoutes.Directory) != 0 {
		extraRoutes, err := loadExtraRoutes(gateway.gateway.ExtraRoutes.Directory)
		if err != nil {
			fmt.Printf("Error: %v\n", err.Error())
		}
		if len(extraRoutes) == 0 {
			fmt.Printf("no extra routes found in %s\n", gateway.gateway.ExtraRoutes.Directory)
		} else {
			dynamicRoutes = append(dynamicRoutes, extraRoutes...)
			fmt.Printf("Loaded %d extra routes from %s\n", len(extraRoutes), gateway.gateway.ExtraRoutes.Directory)
		}
	}
	// Check routes
	checkRoutes(dynamicRoutes, gateway.middlewares)
	fmt.Println("Checking routes...done")

	fmt.Printf("Routes count=%d Middlewares count=%d\n", len(dynamicRoutes), len(gateway.middlewares))

	return nil

}

func checkRoutes(routes []Route, middlewares []Middleware) {
	midNames := middlewareNames(middlewares)
	for index, route := range routes {
		if len(route.Name) == 0 {
			fmt.Printf("Warning: route name is empty, index: [%d]\n", index)
		}
		if route.Destination == "" && len(route.Backends) == 0 {
			fmt.Printf("Error: no destination or backends specified for route: %s | index: [%d] \n", route.Name, index)
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

func middlewareNames(middlewares []Middleware) []string {
	names := []string{}
	for _, mid := range middlewares {
		names = append(names, mid.Name)

	}
	return names
}
