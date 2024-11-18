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
	"github.com/jkaninda/goma-gateway/pkg/logger"
	"gopkg.in/yaml.v3"
	"os"
)

// loadExtraRoutes loads additional routes
func loadExtraRoutes(routePath string) ([]Route, error) {
	logger.Info("Loading additional routes from %s", routePath)
	yamlFiles, err := loadExtraFiles(routePath)
	if err != nil {
		return nil, fmt.Errorf("error loading extra files: %v", err)
	}
	var extraRoutes []Route
	for _, yamlFile := range yamlFiles {
		buf, err := os.ReadFile(yamlFile)
		if err != nil {
			return nil, fmt.Errorf("error loading extra file: %v", err)
		}
		ex := &ExtraRoute{}
		err = yaml.Unmarshal(buf, ex)
		if err != nil {
			return nil, fmt.Errorf("in file %q: %w", ConfigFile, err)
		}
		extraRoutes = append(extraRoutes, ex.Routes...)

	}
	if len(extraRoutes) == 0 {
		return nil, fmt.Errorf("no extra routes found in %s", routePath)
	} else {
		logger.Info("Loaded %d extra routes from %s", len(extraRoutes), routePath)

	}
	return extraRoutes, nil
}

func findDuplicateRouteNames(routes []Route) []string {
	// Create a map to track occurrences of names
	nameMap := make(map[string]int)
	var duplicates []string

	for _, route := range routes {
		nameMap[route.Name]++
		// If the count is ==2, it's a duplicate
		if nameMap[route.Name] == 2 {
			duplicates = append(duplicates, route.Name)
		}
	}
	return duplicates
}
