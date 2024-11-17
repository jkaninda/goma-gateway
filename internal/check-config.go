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
	for index, route := range gateway.gateway.Routes {
		if len(route.Name) == 0 {
			fmt.Printf("Warning: route name is empty, index: [%d]", index)
		}
		if route.Destination == "" && len(route.Backends) == 0 {
			fmt.Printf("Error: no destination or backends specified for route: %s | index: [%d] \n", route.Name, index)
		}
	}

	// Check middlewares
	for index, mid := range c.Middlewares {
		if util.HasWhitespace(mid.Name) {
			fmt.Printf("Warning: Middleware contains whitespace: %s | index: [%d], please remove whitespace characters\n", mid.Name, index)
		}
	}

	fmt.Printf("Routes count=%d Middlewares count=%d\n", len(gateway.gateway.Routes), len(gateway.middlewares))

	return nil

}
