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
	"context"
	"encoding/json"
	"fmt"
	"github.com/fsnotify/fsnotify"
	"gopkg.in/yaml.v3"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type fileProvider struct {
	config  *FileProvider
	watcher *fsnotify.Watcher

	mu      sync.RWMutex
	stopCh  chan struct{}
	stopped bool
}

func NewFileProvider(cfg *FileProvider, stopCh chan struct{}) (Provider, error) {
	if !cfg.Enabled {
		return nil, fmt.Errorf("file provider is not enabled")
	}

	if cfg.Directory == "" {
		return nil, fmt.Errorf("directory is required")
	}

	// Verify directory exists
	if _, err := os.Stat(cfg.Directory); os.IsNotExist(err) {
		return nil, fmt.Errorf("directory does not exist: %s", cfg.Directory)
	}

	return &fileProvider{
		config: cfg,
		stopCh: stopCh,
	}, nil
}

func (p *fileProvider) Name() ProviderType {
	return FileProviderType
}

func (p *fileProvider) Load(ctx context.Context) (*ConfigBundle, error) {
	bundle := &ConfigBundle{
		Routes:      []Route{},
		Middlewares: []Middleware{},
		Metadata:    make(map[string]string),
		Timestamp:   time.Now(),
	}

	configFiles, err := loadAllFiles(p.config.Directory)
	if err != nil {
		return nil, fmt.Errorf("failed to load files: %w", err)
	}
	logger.Debug("found configuration files", "count", len(configFiles))

	for _, file := range configFiles {
		logger.Debug("configuration file", "file", file)
		// Load config based on file extension
		configBundle := &ConfigBundle{}
		if err = p.loadFile(file, configBundle); err != nil {
			return nil, fmt.Errorf("failed to load routes from %s: %w", file, err)
		}
		// Append routes and middlewares
		bundle.Routes = append(bundle.Routes, configBundle.Routes...)
		bundle.Middlewares = append(bundle.Middlewares, configBundle.Middlewares...)
	}
	// Generate version from file modification times
	bundle.Version = p.generateVersion()
	bundle.Checksum = bundle.CalculateChecksum()

	// Validate
	if err = bundle.Validate(); err != nil {
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	logger.Debug("successfully loaded configuration from files",
		"directory", p.config.Directory,
		"version", bundle.Version,
		"routes", len(bundle.Routes),
		"middlewares", len(bundle.Middlewares))

	return bundle, nil
}

func (p *fileProvider) loadFile(path string, target interface{}) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	ext := filepath.Ext(path)
	switch ext {
	case constJsonExt:
		return json.Unmarshal(data, target)
	case constYamlExt, constYmlExt:
		return yaml.Unmarshal(data, target)
	default:
		return fmt.Errorf("unsupported file extension: %s", ext)
	}

}

func (p *fileProvider) generateVersion() string {
	// Generate version based on file modification times
	var latestMod time.Time

	files := []string{"routes.json", "routes.yaml", "middlewares.json", "middlewares.yaml"}
	for _, file := range files {
		path := filepath.Join(p.config.Directory, file)
		if info, err := os.Stat(path); err == nil {
			if info.ModTime().After(latestMod) {
				latestMod = info.ModTime()
			}
		}
	}

	if latestMod.IsZero() {
		return fmt.Sprintf("file-%d", time.Now().Unix())
	}

	return fmt.Sprintf("file-%d", latestMod.Unix())
}

func (p *fileProvider) Watch(ctx context.Context, out chan<- *ConfigBundle) error {
	if !p.config.Watch {
		return fmt.Errorf("file watching is not enabled")
	}

	p.mu.Lock()
	if p.stopped {
		p.mu.Unlock()
		return fmt.Errorf("provider already stopped")
	}
	p.mu.Unlock()

	// Initial load
	bundle, err := p.Load(ctx)
	if err != nil {
		return fmt.Errorf("initial load failed: %w", err)
	}

	// Send initial config
	select {
	case out <- bundle:
	case <-ctx.Done():
		return ctx.Err()
	}

	// Create watcher
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("failed to create watcher: %w", err)
	}

	p.watcher = watcher

	if err = watcher.Add(p.config.Directory); err != nil {
		err = watcher.Close()
		if err != nil {
			return err
		}
		return fmt.Errorf("failed to watch directory: %w", err)
	}

	// Start watching
	go p.watch(ctx, out)

	logger.Debug("file provider watcher started",
		"directory", p.config.Directory)

	return nil
}

func (p *fileProvider) watch(ctx context.Context, out chan<- *ConfigBundle) {
	defer func(watcher *fsnotify.Watcher) {
		err := watcher.Close()
		if err != nil {
			logger.Error("failed to close watcher", "error", err)
		}
	}(p.watcher)

	// Debounce timer
	var debounceTimer *time.Timer
	debounceDuration := 500 * time.Millisecond

	for {
		select {
		case <-ctx.Done():
			logger.Debug("file provider watching stopped: context cancelled")
			return

		case <-p.stopCh:
			logger.Debug("file provider watching stopped")
			return

		case event, ok := <-p.watcher.Events:
			if !ok {
				return
			}

			// Only react to relevant extension changes
			if !p.isRelevantExtension(event.Name) {
				continue
			}

			if event.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Remove) == 0 {
				continue
			}

			logger.Debug("file change detected",
				"file", event.Name,
				"op", event.Op.String())

			// Debounce: reset timer on each event
			if debounceTimer != nil {
				debounceTimer.Stop()
			}

			debounceTimer = time.AfterFunc(debounceDuration, func() {
				p.reloadAndSend(ctx, out)
			})

		case err, ok := <-p.watcher.Errors:
			if !ok {
				return
			}
			logger.Error("watcher error", "error", err)
		}
	}
}

func (p *fileProvider) isRelevantExtension(path string) bool {
	base := filepath.Base(path)
	extensions := []string{".json", ".yaml", ".yml"}
	for _, ext := range extensions {
		if filepath.Ext(base) == ext {
			return true
		}
	}
	return false
}

func (p *fileProvider) reloadAndSend(ctx context.Context, out chan<- *ConfigBundle) {
	logger.Debug("reloading configuration from files")

	bundle, err := p.Load(ctx)
	if err != nil {
		logger.Error("failed to reload configuration", "error", err)
		return
	}

	select {
	case out <- bundle:
		logger.Debug("configuration update sent", "version", bundle.Version)
	case <-ctx.Done():
		return
	case <-time.After(5 * time.Second):
		logger.Warn("timeout sending configuration update")
	}
}

func (p *fileProvider) Stop() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.stopped {
		return nil
	}

	close(p.stopCh)
	p.stopped = true

	if p.watcher != nil {
		err := p.watcher.Close()
		if err != nil {
			return err
		}
	}

	logger.Debug("file provider stopped")
	return nil
}
