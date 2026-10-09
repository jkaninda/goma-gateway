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
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"syscall"
	"time"
)

// passiveHealth ejects a backend endpoint that keeps failing to answer, using
// the traffic already flowing through the gateway rather than a separate
// health-check cron.
type passiveHealth struct {
	mu       sync.RWMutex
	failures map[string]int
	ejected  map[string]time.Time
	maxFails int
	ejectFor time.Duration
	enabled  bool

	now func() time.Time // injectable for tests
}

// newPassiveHealth returns an enabled registry; configure turns it off.
func newPassiveHealth(maxFails int, ejectFor time.Duration) *passiveHealth {
	p := &passiveHealth{
		failures: make(map[string]int),
		ejected:  make(map[string]time.Time),
		now:      time.Now,
	}
	p.configure(maxFails, ejectFor, true)
	return p
}

// configure applies new settings. It is safe to call while requests are being
// served, which is what a configuration reload does. Turning passive checks off
// also forgets every ejection, so no endpoint stays out of rotation on the
// strength of a setting that no longer applies.
func (p *passiveHealth) configure(maxFails int, ejectFor time.Duration, enabled bool) {
	if maxFails < 1 {
		maxFails = defaultPassiveMaxFails
	}
	if ejectFor <= 0 {
		ejectFor = defaultPassiveEjectFor
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.maxFails = maxFails
	p.ejectFor = ejectFor
	p.enabled = enabled
	if !enabled {
		clear(p.failures)
		clear(p.ejected)
	}
}

// recordFailure counts a connection-level failure against an endpoint and
// reports whether that ejected it, and for how long.
func (p *passiveHealth) recordFailure(endpoint string) (bool, time.Duration) {
	if endpoint == "" {
		return false, 0
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.enabled {
		return false, 0
	}
	if _, already := p.ejected[endpoint]; already {
		return false, 0
	}
	p.failures[endpoint]++
	if p.failures[endpoint] < p.maxFails {
		return false, 0
	}
	p.ejected[endpoint] = p.now().Add(p.ejectFor)
	return true, p.ejectFor
}

// recordSuccess clears an endpoint's failure streak.
func (p *passiveHealth) recordSuccess(endpoint string) {
	if endpoint == "" {
		return
	}
	p.mu.RLock()
	_, failing := p.failures[endpoint]
	p.mu.RUnlock()
	if !failing {
		return
	}
	p.mu.Lock()
	delete(p.failures, endpoint)
	p.mu.Unlock()
}

// isEjected reports whether an endpoint is currently out of rotation.
func (p *passiveHealth) isEjected(endpoint string) bool {
	p.mu.RLock()
	until, ok := p.ejected[endpoint]
	p.mu.RUnlock()
	if !ok {
		return false
	}
	if p.now().Before(until) {
		return true
	}
	p.mu.Lock()
	// Re-check: another goroutine may have cleared it already.
	if until, ok := p.ejected[endpoint]; ok && !p.now().Before(until) {
		delete(p.ejected, endpoint)
		p.failures[endpoint] = p.maxFails - 1
	}
	p.mu.Unlock()
	return false
}

func recordBackendFailure(ctx context.Context, endpoint string, err error) {
	if ctx.Err() != nil || !isBackendUnreachable(err) {
		return
	}
	if ejected, ejectFor := passiveBackendHealth.recordFailure(endpoint); ejected {
		prometheusMetrics.GatewayBackendEjections.WithLabelValues(endpoint).Inc()
		logger.Warn("Backend ejected after repeated connection failures",
			"backend", endpoint,
			"eject_for", ejectFor.String(),
			"error", err)
	}
}

// isBackendUnreachable distinguishes "this endpoint is broken" from "this
// request ended for some other reason". Only the former is health information.
func isBackendUnreachable(err error) bool {
	if err == nil || errors.Is(err, context.Canceled) {
		return false
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		return true
	}
	return errors.Is(err, syscall.ECONNREFUSED) ||
		errors.Is(err, syscall.ECONNRESET) ||
		errors.Is(err, syscall.EHOSTUNREACH) ||
		errors.Is(err, syscall.ENETUNREACH) ||
		errors.Is(err, io.EOF) ||
		errors.Is(err, io.ErrUnexpectedEOF)
}

// configurePassiveHealth applies gateway.networking.passiveHealthCheck. Unset
// or invalid values fall back to the defaults.
func configurePassiveHealth(cfg PassiveHealthCheckConfig) {
	ejectFor := defaultPassiveEjectFor
	if raw := strings.TrimSpace(cfg.EjectFor); raw != "" {
		d, err := time.ParseDuration(raw)
		if err != nil || d <= 0 {
			logger.Warn("Invalid networking.passiveHealthCheck.ejectFor, using default",
				"value", raw, "default", defaultPassiveEjectFor.String())
		} else {
			ejectFor = d
		}
	}
	passiveBackendHealth.configure(cfg.MaxFails, ejectFor, cfg.Enabled)
	logger.Debug("Passive health check configured",
		"enabled", cfg.Enabled, "max_fails", passiveBackendHealth.maxFailsValue(), "eject_for", ejectFor.String())
}

func (p *passiveHealth) maxFailsValue() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.maxFails
}
