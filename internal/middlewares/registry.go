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

package middlewares

import (
	"errors"
	"fmt"
	goutils "github.com/jkaninda/go-utils"
	"github.com/jkaninda/goma-gateway/pkg/plugins"
	"path/filepath"
	"plugin"
	"sync"
)

var (
	registry               = make(map[string]plugins.Builder)
	mu                     sync.RWMutex
	ErrPluginNotFound      = errors.New("plugin not found")
	ErrPluginNotRegistered = errors.New("plugin not registered")
)

// Register allows middlewares to self-register
func Register(middlewareType string, constructor func() plugins.Middleware) {
	logger.Debug("Registering middleware", "type", middlewareType)
	mu.Lock()
	defer mu.Unlock()
	registry[middlewareType] = constructor
}

// LoadPlugin loads a .so plugin file and registers it
func LoadPlugin(pluginFile string) error {
	mu.Lock()
	defer mu.Unlock()

	if !goutils.FileExists(pluginFile) {
		return fmt.Errorf("plugin file does not exist: %s", pluginFile)
	}

	// Load the plugin
	p, err := plugin.Open(pluginFile)
	if err != nil {
		return fmt.Errorf("failed to open plugin %s: %w", pluginFile, err)
	}

	// Look for the "New" symbol (constructor function)
	newSymbol, err := p.Lookup("New")
	if err != nil {
		return fmt.Errorf("plugin %s missing 'New' function: %w", pluginFile, err)
	}

	builder, ok := newSymbol.(func() plugins.Middleware)
	if !ok {
		return fmt.Errorf("plugin %s 'New' function has wrong signature, got type: %T, expected: func() plugins.Middleware", pluginFile, newSymbol)
	}

	// Create an instance to get metadata
	instance := (builder)()
	middlewareType := instance.Name()

	if middlewareType == "" {
		// Fallback to filename if no name provided
		middlewareType = filepath.Base(pluginFile)
	}
	logger.Info("Registering plugin middleware", "type", middlewareType, "file", pluginFile)

	// Store the builder
	registry[middlewareType] = builder

	// Optionally get plugin info
	if infoProvider, ok := instance.(plugins.InfoProvider); ok {
		info := infoProvider.Info()
		logger.Info("Loaded plugin", "name", info.Name, "version", info.Version, "author", info.Author)
	}

	return nil
}

// LoadPluginsFromDir loads all .so files from a directory
func LoadPluginsFromDir(dirPath string) error {
	matches, err := filepath.Glob(filepath.Join(dirPath, "*.so"))
	if err != nil {
		return err
	}

	var errs []error
	for _, pluginPath := range matches {
		if err := LoadPlugin(pluginPath); err != nil {
			errs = append(errs, err)
			fmt.Printf("Warning: failed to load plugin %s: %v\n", pluginPath, err)
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("failed to load %d plugin(s)", len(errs))
	}

	return nil
}

// Create instantiates a middleware from configuration
//
// parameters:
// middlewareType is the registered type name
// paths are the specific paths the middleware should apply to
// rule is the configuration rule for the middleware
func Create(middlewareType string, paths []string, rule interface{}) (plugins.Middleware, error) {
	mu.RLock()
	builder, exists := registry[middlewareType]
	mu.RUnlock()

	if !exists {
		return nil, ErrPluginNotFound
	}

	// Create new instance
	instance := builder()

	// Configure the middleware
	if err := instance.Configure(rule); err != nil {
		return nil, fmt.Errorf("failed to configure middleware: %w", err)
	}
	// Validate the middleware
	if err := instance.Validate(); err != nil {
		return nil, fmt.Errorf("middleware validation failed: %w", err)
	}

	// If the middleware supports paths, pass them in
	if pathAware, ok := instance.(plugins.PathAware); ok {
		pathAware.WithPaths(paths)
	}

	return instance, nil
}

// GetMiddleware returns a new instance by name
func GetMiddleware(name string) (plugins.Middleware, error) {
	if constructor, ok := registry[name]; ok {
		return constructor(), nil
	}
	return nil, fmt.Errorf("middleware not found: %s", name)
}

// List returns all registered middleware types
func List() []string {
	mu.RLock()
	defer mu.RUnlock()

	types := make([]string, 0, len(registry))
	for t := range registry {
		types = append(types, t)
	}
	return types
}
