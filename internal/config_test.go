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
	"github.com/jkaninda/goma-gateway/internal/middlewares"
	"github.com/jkaninda/goma-gateway/internal/version"
	"gopkg.in/yaml.v3"
	"os"
)

func initTestConfig(configFile string) error {
	if configFile == "" {
		configFile = GetConfigPaths()
	}
	conf := &GatewayConfig{
		Version: version.ConfigVersion,
		GatewayConfig: Gateway{
			WriteTimeout: 15,
			ReadTimeout:  15,
			IdleTimeout:  30,
			ExtraConfig: ExtraRouteConfig{
				Directory: extraRoutePath,
				Watch:     true,
			},
			Routes: []Route{
				{
					Name:    "Example",
					Path:    "/",
					Methods: []string{"GET", "PATCH", "OPTIONS"},
					Backends: Backends{
						&Backend{Endpoint: "https://example.com"},
					},
					HealthCheck: RouteHealthCheck{
						Path:            "/",
						Interval:        "30s",
						Timeout:         "10s",
						HealthyStatuses: []int{200, 404},
					},
					DisableHostForwarding: true,
					Middlewares:           []string{"block-access"},
				},
				{
					Name:    "round-robin-load-balancing",
					Path:    "/load-balancing",
					Methods: []string{"GET", "OPTIONS"},
					Backends: Backends{
						&Backend{Endpoint: "https://example.com"},
						&Backend{Endpoint: "https://example1.com"},
						&Backend{Endpoint: "https://example2.com"},
					},
					HealthCheck: RouteHealthCheck{
						Path:            "/",
						Interval:        "30s",
						Timeout:         "10s",
						HealthyStatuses: []int{200, 404},
					},
					DisableHostForwarding: true,
					Middlewares:           []string{"block-access"},
				},
				{
					Name: "weighted-load-balancing",
					Path: "/load-balancing2",
					Backends: Backends{
						&Backend{Endpoint: "https://example.com", Weight: 5},
						&Backend{Endpoint: "https://example1.com", Weight: 2},
						&Backend{Endpoint: "https://example2.com", Weight: 1},
					},
					Rewrite:               "/",
					DisableHostForwarding: false,
					ErrorInterceptor: middlewares.RouteErrorInterceptor{
						Enabled:     true,
						ContentType: applicationJson,
						Errors: []middlewares.RouteError{
							{
								StatusCode: 403,
								Body:       "403 Forbidden",
							},
							{
								StatusCode: 404,
								Body:       "{\"error\": \"404 Not Found\"}",
							},
							{
								StatusCode: 500,
							},
						},
					},
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
					Realm: "Restricted",
					Users: []middlewares.User{
						{Username: "admin", Password: "$2y$05$TIx7l8sJWvMFXw4n0GbkQuOhemPQOormacQC4W1p28TOVzJtx.XpO"},
						{Username: "admin", Password: "admin"},
					},
				},
			},
			{
				Name: "block-access",
				Type: AccessMiddleware,
				Paths: []string{
					"/swagger-ui/*",
					"/api-docs/*",
					"/actuator/*",
				},
			},
			{
				Name: "access-policy",
				Type: accessPolicy,
				Rule: AccessPolicyRuleMiddleware{
					Action: "DENY",
					SourceRanges: []string{
						"10.1.10.0/16",
						"192.168.1.25-192.168.1.100",
						"192.168.1.115",
					},
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
