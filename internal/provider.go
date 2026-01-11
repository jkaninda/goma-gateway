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
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"gopkg.in/yaml.v3"
	"os"
	"path/filepath"
	"time"
)

var (
	ErrInvalidVersion              = errors.New("invalid_version, version is required")
	GitProviderType   ProviderType = "git"
	HttpProviderType  ProviderType = "http"
	FileProviderType  ProviderType = "file"
	gomaCacheFile                  = filepath.Join(os.TempDir(), "goma/cache/config.json")
)

// Provider defines the interface for configuration providers
type Provider interface {
	Name() ProviderType
	Load(ctx context.Context) (*ConfigBundle, error)
	Watch(ctx context.Context, out chan<- *ConfigBundle) error
	Stop() error
}

// ConfigBundle represents the complete gateway configuration
type ConfigBundle struct {
	Version     string            `json:"version" yaml:"version"`
	Routes      []Route           `json:"routes" yaml:"routes"`
	Middlewares []Middleware      `json:"middlewares" yaml:"middlewares"`
	Metadata    map[string]string `json:"metadata,omitempty" yaml:"metadata,omitempty"`
	Checksum    string            `json:"checksum,omitempty" yaml:"checksum,omitempty"`
	Timestamp   time.Time         `json:"timestamp" yaml:"timestamp"`
}
type ProviderType string
type Providers struct {
	File *FileProvider `yaml:"file"`
	HTTP *HTTPProvider `yaml:"http"`
	Git  *GitProvider  `yaml:"git"`
}
type FileProvider struct {
	Enabled   bool   `yaml:"enabled"`
	Directory string `yaml:"directory"`
	Watch     bool   `yaml:"watch"`
}

// CalculateChecksum computes the SHA256 checksum of the config bundle
func (cb *ConfigBundle) CalculateChecksum() string {
	temp := *cb
	temp.Checksum = ""
	temp.Timestamp = time.Time{}

	data, err := yaml.Marshal(temp)
	if err != nil {
		return ""
	}

	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// Validate validates the configuration bundle
func (cb *ConfigBundle) Validate() error {
	if cb.Version == "" {
		return ErrInvalidVersion
	}

	return nil
}

// Clone creates a deep copy of ConfigBundle
func (cb *ConfigBundle) Clone() *ConfigBundle {
	if cb == nil {
		return nil
	}

	clone := &ConfigBundle{
		Version:   cb.Version,
		Checksum:  cb.Checksum,
		Timestamp: cb.Timestamp,
		Metadata:  make(map[string]string),
	}

	// Clone routes
	clone.Routes = make([]Route, len(cb.Routes))
	copy(clone.Routes, cb.Routes)

	// Clone middlewares
	clone.Middlewares = make([]Middleware, len(cb.Middlewares))
	copy(clone.Middlewares, cb.Middlewares)

	// Clone metadata
	for k, v := range cb.Metadata {
		clone.Metadata[k] = v
	}

	return clone
}
