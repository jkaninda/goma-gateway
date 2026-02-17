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
	"fmt"
	"strings"
	"sync"
	"time"
)

type ProviderManager struct {
	providers       []Provider
	mu              sync.RWMutex
	stopCh          chan struct{}
	configCh        chan *ConfigBundle
	configBundle    *ConfigBundle
	providerBundles map[ProviderType]*ConfigBundle
}

func newManager() *ProviderManager {
	return &ProviderManager{
		providers:       []Provider{},
		stopCh:          make(chan struct{}),
		configCh:        make(chan *ConfigBundle, 10),
		providerBundles: make(map[ProviderType]*ConfigBundle),
	}
}

func (m *ProviderManager) Register(provider Provider) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.providers = append(m.providers, provider)
	logger.Debug("provider registered", "name", provider.Name())

	return nil
}

func (m *ProviderManager) Load(ctx context.Context) (*ConfigBundle, error) {
	m.mu.RLock()
	providers := make([]Provider, len(m.providers))
	copy(providers, m.providers)
	m.mu.RUnlock()

	if len(providers) == 0 {
		return nil, fmt.Errorf("no providers configured")
	}

	for _, p := range providers {
		bundle, err := p.Load(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to load from %s provider: %w", p.Name(), err)
		}
		m.mu.Lock()
		m.providerBundles[p.Name()] = bundle
		m.mu.Unlock()
	}

	m.mu.RLock()
	merged := m.mergeBundles()
	m.mu.RUnlock()

	return merged, nil
}

// mergeBundles combines all provider bundles into a single ConfigBundle.
func (m *ProviderManager) mergeBundles() *ConfigBundle {
	merged := &ConfigBundle{
		Routes:      []Route{},
		Middlewares: []Middleware{},
		Metadata:    make(map[string]string),
		Timestamp:   time.Now(),
	}

	var versions []string
	providerOrder := []ProviderType{FileProviderType, HttpProviderType, GitProviderType}
	for _, pt := range providerOrder {
		bundle, ok := m.providerBundles[pt]
		if !ok || bundle == nil {
			continue
		}
		merged.Routes = append(merged.Routes, bundle.Routes...)
		merged.Middlewares = append(merged.Middlewares, bundle.Middlewares...)
		for k, v := range bundle.Metadata {
			merged.Metadata[k] = v
		}
		versions = append(versions, fmt.Sprintf("%s:%s", pt, bundle.Version))
	}

	if len(versions) > 0 {
		merged.Version = strings.Join(versions, ",")
	} else {
		merged.Version = fmt.Sprintf("merged-%d", time.Now().Unix())
	}
	merged.Checksum = merged.CalculateChecksum()

	return merged
}

func (m *ProviderManager) Watch(ctx context.Context) (<-chan *ConfigBundle, error) {
	m.mu.RLock()
	providers := make([]Provider, len(m.providers))
	copy(providers, m.providers)
	m.mu.RUnlock()

	if len(providers) == 0 {
		return nil, fmt.Errorf("no providers configured")
	}

	watchCount := 0
	for _, p := range providers {
		providerCh := make(chan *ConfigBundle, 5)

		if err := p.Watch(ctx, providerCh); err != nil {
			logger.Warn("provider does not support watching, skipping", "provider", p.Name(), "error", err)
			continue
		}
		watchCount++

		go func(provider Provider, ch <-chan *ConfigBundle) {
			for {
				select {
				case <-ctx.Done():
					return
				case <-m.stopCh:
					return
				case bundle, ok := <-ch:
					if !ok {
						return
					}
					m.mu.Lock()
					m.providerBundles[provider.Name()] = bundle
					merged := m.mergeBundles()
					m.mu.Unlock()

					select {
					case m.configCh <- merged:
						logger.Debug("merged configuration update sent", "source", provider.Name())
					case <-ctx.Done():
						return
					case <-m.stopCh:
						return
					}
				}
			}
		}(p, providerCh)
	}

	if watchCount == 0 {
		return nil, fmt.Errorf("no providers support watching")
	}

	return m.configCh, nil
}

func (m *ProviderManager) StopAll() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, provider := range m.providers {
		if err := provider.Stop(); err != nil {
			logger.Error("failed to stop provider", "name", provider.Name(), "error", err)
		}
	}

	close(m.stopCh)
	logger.Debug("All providers stopped")
	return nil
}

func (m *ProviderManager) hasActiveProvider() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.providers) > 0
}

func (m *ProviderManager) activeProvider() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if len(m.providers) == 0 {
		return ""
	}
	names := make([]string, 0, len(m.providers))
	for _, p := range m.providers {
		names = append(names, string(p.Name()))
	}
	return strings.Join(names, ", ")
}

func (m *ProviderManager) isConfigured() bool {
	return m != nil && m.hasActiveProvider() && m.configBundle != nil
}
