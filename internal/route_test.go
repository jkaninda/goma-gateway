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
)

// initExtraRoute create extra routes
func initExtraRoute(path string) error {

	conf := &ExtraRoute{
		Routes: []Route{
			{
				Name:        "Extra1",
				Path:        "/",
				Methods:     []string{"GET"},
				Destination: "https://extra-example.com",
				Rewrite:     "/",
				HealthCheck: RouteHealthCheck{
					Path:            "/",
					Interval:        "30s",
					Timeout:         "10s",
					HealthyStatuses: []int{200, 404},
				},
				DisableHostFording: true,
				Middlewares:        []string{"block-access"},
			},
			// Duplicate route name
			{
				Name: "Load balancer",
				Path: "/protected",
				Backends: []string{
					"https://example.com",
					"https://example2.com",
					"https://example3.com",
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

// initConfig initializes configs
func initConfiguration(configFile string) error {
	conf := &GatewayConfig{
		Version: util.ConfigVersion,
		GatewayConfig: Gateway{
			WriteTimeout:                 15,
			ReadTimeout:                  15,
			IdleTimeout:                  30,
			AccessLog:                    "/dev/Stdout",
			ErrorLog:                     "/dev/stderr",
			DisableRouteHealthCheckError: false,
			DisableDisplayRouteOnStart:   false,
			RateLimit:                    0,
			InterceptErrors:              []int{405, 500},
			ExtraRoutes: ExtraRouteConfig{
				Directory: extraRoutePath,
				Watch:     false,
			},
			Cors: Cors{
				Origins: []string{"http://localhost:8080", "https://example.com"},
				Headers: map[string]string{
					"Access-Control-Allow-Headers":     "Origin, Authorization, Accept, Content-Type, Access-Control-Allow-Headers",
					"Access-Control-Allow-Credentials": "true",
					"Access-Control-Max-Age":           "1728000",
				},
			},
			Routes: []Route{
				{
					Name:        "Example",
					Path:        "/",
					Methods:     []string{"GET"},
					Destination: "https://example.com",
					Rewrite:     "/",
					HealthCheck: RouteHealthCheck{
						Path:            "/",
						Interval:        "30s",
						Timeout:         "10s",
						HealthyStatuses: []int{200, 404},
					},
					DisableHostFording: true,
					Middlewares:        []string{"block-access"},
				},
				{
					Name: "Load balancer",
					Path: "/protected",
					Backends: []string{
						"https://example.com",
						"https://example2.com",
						"https://example3.com",
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
		},
		Middlewares: []Middleware{
			{
				Name: "basic-auth",
				Type: BasicAuth,
				Paths: []string{
					"/*",
				},
				Rule: BasicRuleMiddleware{
					Username: "admin",
					Password: "admin",
				},
			},
			{
				Name: "block-access",
				Type: AccessMiddleware,
				Paths: []string{
					"/swagger-ui/*",
					"/v2/swagger-ui/*",
					"/api-docs/*",
					"/actuator/*",
				},
			},
		},
	}
	yamlData, err := yaml.Marshal(&conf)
	if err != nil {
		return fmt.Errorf("serializing configuration %v\n", err.Error())
	}
	err = os.WriteFile(configFile, yamlData, 0644)
	if err != nil {
		return fmt.Errorf("unable to write config file %s\n", err)
	}
	return nil
}
