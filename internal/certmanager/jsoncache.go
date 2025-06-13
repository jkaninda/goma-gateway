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

package certmanager

import (
	"context"
	"encoding/json"
	"fmt"
	"golang.org/x/crypto/acme/autocert"
	"os"
	"path/filepath"
	"sync"
)

type JSONCache struct {
	filePath string
	mu       sync.Mutex
	data     map[string][]byte
}

// newJSONCache loads or initializes a JSON-based autocert.Cache.
func newJSONCache(filePath string) (*JSONCache, error) {

	if err := os.MkdirAll(filepath.Dir(filePath), 0700); err != nil {
		return nil, fmt.Errorf("create cache directory: %w", err)
	}
	cache := &JSONCache{
		filePath: filePath,
		data:     make(map[string][]byte),
	}
	// Only read if file exists
	if _, err := os.Stat(filePath); err == nil {
		raw, err := os.ReadFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("read cache file: %w", err)
		}
		if err := json.Unmarshal(raw, &cache.data); err != nil {
			return nil, fmt.Errorf("unmarshal cache: %w", err)
		}
	}

	return cache, nil
}

func (c *JSONCache) Get(_ context.Context, key string) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	val, exists := c.data[key]
	if !exists {
		return nil, autocert.ErrCacheMiss
	}
	return val, nil
}

func (c *JSONCache) Put(_ context.Context, key string, data []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.data[key] = data
	return c.save()
}

func (c *JSONCache) Delete(_ context.Context, key string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	delete(c.data, key)
	return c.save()
}

func (c *JSONCache) save() error {
	jsonData, err := json.MarshalIndent(c.data, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal cache data: %w", err)
	}
	return os.WriteFile(c.filePath, jsonData, 0600)
}
