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
	"crypto/tls"
	"encoding/json"
	"fmt"
	goutils "github.com/jkaninda/go-utils"
	"github.com/jkaninda/goma-gateway/internal/version"
	"gopkg.in/yaml.v3"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// HTTPProvider configuration
type HTTPProvider struct {
	Enabled            bool              `yaml:"enabled" json:"enabled"`
	Endpoint           string            `yaml:"endpoint" json:"endpoint"`
	Interval           time.Duration     `yaml:"interval" json:"interval"`
	Headers            map[string]string `yaml:"headers,omitempty" json:"headers,omitempty"`
	Timeout            time.Duration     `yaml:"timeout" json:"timeout"`
	InsecureSkipVerify bool              `yaml:"insecureSkipVerify" json:"insecureSkipVerify"`
	RetryAttempts      int               `yaml:"retryAttempts" json:"retryAttempts"`
	RetryDelay         time.Duration     `yaml:"retryDelay" json:"retryDelay"`
	CacheDir           string            `yaml:"cacheDir,omitempty" json:"cacheDir,omitempty"`
}
type httpProvider struct {
	config *HTTPProvider
	client *http.Client

	mu         sync.RWMutex
	lastBundle *ConfigBundle
	stopCh     chan struct{}
	stopped    bool
}

func NewHTTPProvider(cfg *HTTPProvider) (Provider, error) {
	if !cfg.Enabled {
		return nil, fmt.Errorf("HTTP provider is not enabled")
	}

	if cfg.Endpoint == "" {
		return nil, fmt.Errorf("endpoint is required")
	}

	// Set defaults
	if cfg.Interval == 0 {
		cfg.Interval = 30 * time.Second
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 10 * time.Second
	}
	if cfg.RetryAttempts == 0 {
		cfg.RetryAttempts = 3
	}
	if cfg.RetryDelay == 0 {
		cfg.RetryDelay = 2 * time.Second
	}
	if cfg.CacheDir == "" {
		cfg.CacheDir = gomaCacheFile
	}

	// Create HTTP client
	transport := &http.Transport{
		MaxIdleConns:        100,
		IdleConnTimeout:     90 * time.Second,
		DisableCompression:  false,
		TLSHandshakeTimeout: 10 * time.Second,
	}

	if cfg.InsecureSkipVerify {
		transport.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true,
		}
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   cfg.Timeout,
	}

	return &httpProvider{
		config: cfg,
		client: client,
		stopCh: stopChan,
	}, nil
}

func (p *httpProvider) Name() ProviderType {
	return HttpProviderType
}

func (p *httpProvider) Load(ctx context.Context) (*ConfigBundle, error) {
	var lastErr error

	for attempt := 0; attempt < p.config.RetryAttempts; attempt++ {
		if attempt > 0 {
			logger.Debug("retrying HTTP fetch",
				"attempt", attempt+1,
				"max_attempts", p.config.RetryAttempts)

			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(p.config.RetryDelay):
			}
		}

		bundle, err := p.fetch(ctx)
		if err == nil {
			// Update cache
			p.updateCache(bundle)

			p.mu.Lock()
			p.lastBundle = bundle
			p.mu.Unlock()

			logger.Debug("successfully loaded configuration from HTTP",
				"version", bundle.Version,
				"routes", len(bundle.Routes),
				"middlewares", len(bundle.Middlewares))

			return bundle, nil
		}

		lastErr = err
		logger.Warn("HTTP fetch attempt failed", "attempt", attempt+1, " error", err)
	}

	// All attempts failed, try cache
	logger.Error("all HTTP fetch attempts failed, trying cache", "error", lastErr)

	if len(p.config.CacheDir) != 0 {
		if cached := p.loadFromCache(); cached != nil {
			logger.Info("loaded configuration from cache",
				"version", cached.Version)
			return cached, nil
		}
	}

	return nil, fmt.Errorf("failed to load configuration and no cache available: %w", lastErr)
}

func (p *httpProvider) fetch(ctx context.Context) (*ConfigBundle, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.config.Endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("Accept", "application/json, application/yaml, application/x-yaml, text/yaml")
	req.Header.Set("User-Agent", fmt.Sprintf("goma-gateway/%s", version.Version))

	for key, value := range p.config.Headers {
		req.Header.Set(key, goutils.ReplaceEnvVars(value))
	}

	// Send last known version for conditional fetch
	p.mu.RLock()
	if p.lastBundle != nil {
		req.Header.Set("If-None-Match", p.lastBundle.Version)
	}
	p.mu.RUnlock()

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer func(Body io.ReadCloser) {
		err = Body.Close()
		if err != nil {
			logger.Error("failed to close response body", "error", err)
		}
	}(resp.Body)

	// Handle 304 Not Modified
	if resp.StatusCode == http.StatusNotModified {
		p.mu.RLock()
		defer p.mu.RUnlock()

		if p.lastBundle != nil {
			logger.Debug("configuration not modified",
				"version", p.lastBundle.Version)
			return p.lastBundle.Clone(), nil
		}
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Detect content type
	contentType := resp.Header.Get("Content-Type")
	format := p.detectFormat(contentType, body)

	logger.Debug("detected response format",
		"content_type", contentType,
		"format", format)

	var bundle ConfigBundle

	switch format {
	case constYaml:
		if err = yaml.Unmarshal(body, &bundle); err != nil {
			return nil, fmt.Errorf("failed to unmarshal YAML config: %w", err)
		}
	case constJson:
		if err = json.Unmarshal(body, &bundle); err != nil {
			return nil, fmt.Errorf("failed to unmarshal JSON config: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported format: %s (content-type: %s)", format, contentType)
	}

	// Verify checksum if provided
	if bundle.Checksum != "" {
		calculated := bundle.CalculateChecksum()
		if calculated != bundle.Checksum {
			return nil, fmt.Errorf("checksum mismatch: expected %s, got %s",
				bundle.Checksum, calculated)
		}
	} else {
		// Calculate and set checksum
		bundle.Checksum = bundle.CalculateChecksum()
	}

	if bundle.Timestamp.IsZero() {
		bundle.Timestamp = time.Now()
	}

	return &bundle, nil
}

// detectFormat determines the format based on Content-Type header and content inspection
func (p *httpProvider) detectFormat(contentType string, body []byte) string {
	contentType = strings.ToLower(contentType)

	if strings.Contains(contentType, "yaml") ||
		strings.Contains(contentType, "x-yaml") {
		return constYaml
	}

	if strings.Contains(contentType, constJson) {
		return constJson
	}

	// If Content-Type is not set, try to detect from content
	// Trim leading whitespace
	trimmed := strings.TrimLeft(string(body), " \t\n\r")

	if len(trimmed) == 0 {
		return "unknown"
	}

	if trimmed[0] == '{' || trimmed[0] == '[' {
		return constJson
	}

	// YAML might start with --- or have key: value patterns
	if strings.HasPrefix(trimmed, "---") {
		return constYaml
	}

	// Try to detect YAML key-value pattern (key: value)
	lines := strings.Split(trimmed, "\n")
	for _, line := range lines[:_min(10, len(lines))] {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.Contains(line, ":") && !strings.HasPrefix(line, "{") {
			return constYaml
		}
		break
	}

	// Default to JSON
	return constJson
}

func _min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (p *httpProvider) Watch(ctx context.Context, out chan<- *ConfigBundle) error {
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

	// Start polling
	go p.poll(ctx, out)

	logger.Debug("HTTP provider watcher started",
		"endpoint", p.config.Endpoint,
		"interval", p.config.Interval)

	return nil
}

func (p *httpProvider) poll(ctx context.Context, out chan<- *ConfigBundle) {
	ticker := time.NewTicker(p.config.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			logger.Debug("HTTP provider polling stopped: context cancelled")
			return

		case <-p.stopCh:
			logger.Debug("HTTP provider polling stopped")
			return

		case <-ticker.C:
			bundle, err := p.Load(ctx)
			if err != nil {
				logger.Error("failed to poll configuration", "error", err)
				continue
			}

			// Check if config changed
			p.mu.RLock()
			changed := p.lastBundle == nil ||
				p.lastBundle.Version != bundle.Version ||
				p.lastBundle.Checksum != bundle.Checksum
			p.mu.RUnlock()

			if !changed {
				logger.Debug("no configuration changes detected",
					"version", bundle.Version)
				continue
			}

			logger.Info("configuration update detected",
				"version", bundle.Version)

			// Send update
			select {
			case out <- bundle:
				logger.Debug("configuration update sent to channel")
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Second):
				logger.Warn("timeout sending configuration update")
			}
		}
	}
}

func (p *httpProvider) Stop() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.stopped {
		return nil
	}

	close(p.stopCh)
	p.stopped = true

	logger.Info("HTTP provider stopped")
	return nil
}

func (p *httpProvider) updateCache(bundle *ConfigBundle) {
	if p.config.CacheDir == "" {
		// Use default cache path
		p.config.CacheDir = filepath.Join(os.TempDir(), gomaCacheFile)
	}

	// Determine cache format from path extension
	format := p.getCacheFormat()

	var data []byte
	var err error

	switch format {
	case constYaml:
		data, err = yaml.Marshal(bundle)
	case constJson:
		data, err = json.MarshalIndent(bundle, "", "  ")
	default:
		data, err = json.MarshalIndent(bundle, "", "  ")
	}

	if err != nil {
		logger.Error("failed to marshal cache", "error", err)
		return
	}

	// Extract dir from cache file path
	cacheDir := filepath.Dir(p.config.CacheDir)

	// Create dir if not exists
	if err = os.MkdirAll(cacheDir, 0755); err != nil {
		logger.Error("failed to create cache directory", "dir", cacheDir, "error", err)
		return
	}
	if err := os.WriteFile(p.config.CacheDir, data, 0644); err != nil {
		logger.Error("failed to write cache", "error", err)
	} else {
		logger.Debug("cache updated successfully",
			"path", p.config.CacheDir,
			"format", format)
	}
}

func (p *httpProvider) loadFromCache() *ConfigBundle {
	if len(p.config.CacheDir) == 0 {
		return nil
	}
	data, err := os.ReadFile(p.config.CacheDir)
	if err != nil {
		logger.Debug("failed to read cache file", "error", err)
		return nil
	}

	format := p.getCacheFormat()

	var bundle ConfigBundle

	switch format {
	case "yaml":
		if err = yaml.Unmarshal(data, &bundle); err != nil {
			logger.Error("failed to unmarshal YAML cache", "error", err)
			return nil
		}
	case constJson:
		if err = json.Unmarshal(data, &bundle); err != nil {
			logger.Error("failed to unmarshal JSON cache", " error", err)
			return nil
		}
	default:
		// Try JSON first, then YAML
		if err = json.Unmarshal(data, &bundle); err != nil {
			if err = yaml.Unmarshal(data, &bundle); err != nil {
				logger.Error("failed to unmarshal cache (tried both JSON and YAML)", "error", err)
				return nil
			}
		}
	}

	logger.Debug("cache loaded successfully",
		"path", p.config.CacheDir,
		"format", format,
		"version", bundle.Version)

	return &bundle
}

func (p *httpProvider) getCacheFormat() string {
	ext := strings.ToLower(filepath.Ext(p.config.CacheDir))

	switch ext {
	case constYamlExt, constYmlExt:
		return "yaml"
	case constJsonExt:
		return "json"
	default:
		return "json"
	}
}
