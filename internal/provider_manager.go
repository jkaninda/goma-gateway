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
	"sync"
)

type ProviderManager struct {
	providers    []Provider
	active       Provider
	mu           sync.RWMutex
	stopCh       chan struct{}
	configCh     chan *ConfigBundle
	configBundle *ConfigBundle
}

func newManager() *ProviderManager {
	return &ProviderManager{
		providers: []Provider{},
		stopCh:    make(chan struct{}),
		configCh:  make(chan *ConfigBundle, 10),
	}
}

func (m *ProviderManager) Register(provider Provider) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.providers = append(m.providers, provider)
	logger.Debug("provider registered", "name", provider.Name())

	return nil
}

func (m *ProviderManager) SetActive(name ProviderType) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, p := range m.providers {
		if p.Name() == name {
			m.active = p
			logger.Debug("active provider set", "name", name)
			return nil
		}
	}

	return fmt.Errorf("provider not found: %s", name)
}

func (m *ProviderManager) Load(ctx context.Context) (*ConfigBundle, error) {
	m.mu.RLock()
	provider := m.active
	m.mu.RUnlock()

	if provider == nil {
		return nil, fmt.Errorf("no active provider")
	}

	return provider.Load(ctx)
}

func (m *ProviderManager) Watch(ctx context.Context) (<-chan *ConfigBundle, error) {
	m.mu.RLock()
	provider := m.active
	m.mu.RUnlock()

	if provider == nil {
		return nil, fmt.Errorf("no active provider")
	}

	if err := provider.Watch(ctx, m.configCh); err != nil {
		return nil, err
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
	if len(m.providers) == 0 {
		logger.Debug("no active providers")
		return false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.active != nil
}
func (m *ProviderManager) activeProvider() ProviderType {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.active != nil {
		return m.active.Name()
	}
	return ""
}
func (m *ProviderManager) isConfigured() bool {
	return m != nil && m.hasActiveProvider() && m.configBundle != nil
}
