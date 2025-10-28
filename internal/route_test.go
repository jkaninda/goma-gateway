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
	"fmt"
	"gopkg.in/yaml.v3"
	"os"
)

// initExtraRoute create extra routes
func initExtraRoute(path string) error {

	conf := &ExtraRoute{
		Routes: []Route{
			{
				Name:    "Extra1",
				Path:    "/extra",
				Methods: []string{"GET"},
				Backends: Backends{
					&Backend{Endpoint: "https://extra-example.com"},
				},
				Rewrite: "/",
				HealthCheck: RouteHealthCheck{
					Path:            "/",
					Interval:        "30s",
					Timeout:         "10s",
					HealthyStatuses: []int{200, 404},
				},
				Middlewares: []string{"block-access"},
			},
			{
				Name:    "example",
				Path:    "/example",
				Methods: []string{"GET"},
				Backends: Backends{
					&Backend{Endpoint: "https://example.com"},
				},
				Rewrite: "/",
				HealthCheck: RouteHealthCheck{
					Path:            "/",
					Interval:        "30s",
					Timeout:         "10s",
					HealthyStatuses: []int{200, 404},
				},
				Middlewares: []string{"basic-auth"},
			},
			// Duplicate route name
			{
				Name: "weighted-load-balancing",
				Path: "/weighted-extra",
				Backends: Backends{
					&Backend{Endpoint: "https://example.com", Weight: 5},
					&Backend{Endpoint: "https://example1.com", Weight: 2},
					&Backend{Endpoint: "https://example2.com", Weight: 1},
				},
				Rewrite:     "/",
				HealthCheck: RouteHealthCheck{},
				Cors: Cors{
					Origins: []string{"http://localhost:3000", "https://dev.example.com"},
					Headers: map[string]string{
						"Access-Control-Allow-Headers":     "Origin, Authorization",
						"Access-Control-Allow-Credentials": "true",
						"Access-Control-Max-Age":           "1728000",
					},
				},
				Middlewares: []string{"basic-auth", "block-access"},
			},
		},
	}
	yamlData, err := yaml.Marshal(&conf)
	if err != nil {
		return fmt.Errorf("serializing configuration %v\n", err.Error())
	}
	err = os.WriteFile(fmt.Sprintf("%s/extra.yaml", path), yamlData, 0644)
	if err != nil {
		return fmt.Errorf("unable to write config file %s\n", err)
	}
	return nil
}
