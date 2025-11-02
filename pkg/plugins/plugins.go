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

package plugins

import "net/http"

// Middleware represents a pluggable middleware component
type Middleware interface {
	// Name returns the unique identifier for this middleware
	Name() string

	// Handler wraps an http.Handler with middleware logic
	Handler(next http.Handler) http.Handler

	Validate() error

	// Configure initializes the middleware with configuration
	Configure(rule interface{}) error
}

// Builder is the function signature that plugins must export
// This function will be looked up via plugin.Lookup("New")
type Builder func() Middleware

type Info struct {
	Name        string
	Version     string
	Author      string
	Description string
}

// InfoProvider can be optionally implemented to provide plugin metadata
type InfoProvider interface {
	Info() Info
}

type PathAware interface {
	WithPaths(paths []string)
}
