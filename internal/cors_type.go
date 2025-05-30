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

// Cors defines the configuration structure for Cross-Origin Resource Sharing (CORS) settings
type Cors struct {
	// Origins specifies which origins are allowed to access the resource.
	// Examples:
	// - http://localhost:80
	// - https://example.com
	Origins []string `yaml:"origins"`

	// AllowedHeaders defines which request headers are permitted in actual requests
	AllowedHeaders []string `yaml:"allowedHeaders"`

	// Headers contains custom headers to be set in the response
	Headers map[string]string `yaml:"headers"`

	// ExposeHeaders indicates which response headers can be exposed to the client
	ExposeHeaders []string `yaml:"exposeHeaders"`

	// MaxAge defines how long (in seconds) the results of a preflight request can be cached
	MaxAge int `yaml:"maxAge"`

	// AllowMethods lists the HTTP methods permitted for cross-origin requests
	AllowMethods []string `yaml:"allowMethods"`

	// AllowCredentials indicates whether the response can include credentials (cookies, HTTP auth)
	AllowCredentials bool `yaml:"allowCredentials"`
}
