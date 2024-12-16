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

// Middleware defines the route middlewares configuration.
type Middleware struct {
	// Name specifies the unique name of the middleware.
	Name string `yaml:"name"`

	// Type indicates the type of middleware.
	// Supported types: "basic", "jwt", "oauth", "rateLimit", "access", "accessPolicy.
	Type string `yaml:"type"`

	// Paths lists the routes or paths that this middleware will protect.
	Paths []string `yaml:"paths"`

	// Rule represents the specific configuration or rules for the middleware.
	// The structure of Rule depends on the middleware Type. For example:
	// - "rateLimit" might use a struct defining rate limits.
	// - "accessPolicy" could use a struct specifying accessPolicy control rules.
	Rule interface{} `yaml:"rule"`
}
