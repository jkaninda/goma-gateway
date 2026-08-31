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

import "sync"

// backendHealth records which backend endpoints the health checks have marked
// unavailable.
//
// The health-check crons write this while every proxied request on a
// multi-backend route reads it. It used to be a bare map with no
// synchronisation: Go's runtime *fatals* on a concurrent map read and write —
// not a recoverable panic — so a backend flapping under normal traffic could
// take the whole gateway down. Backend selection also mutated a shared
// Backend.unavailable field from the request path; selection now reads this
// registry directly instead, so nothing on the request path writes at all.
type backendHealth struct {
	mu          sync.RWMutex
	unavailable map[string]bool
}

func newBackendHealth() *backendHealth {
	return &backendHealth{unavailable: make(map[string]bool)}
}

func (h *backendHealth) markUnavailable(endpoint string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.unavailable[endpoint] = true
}

// markAvailable clears an endpoint and reports whether it had been marked,
// so the caller can log a recovery only when there was something to recover.
func (h *backendHealth) markAvailable(endpoint string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.unavailable[endpoint] {
		return false
	}
	delete(h.unavailable, endpoint)
	return true
}

func (h *backendHealth) isUnavailable(endpoint string) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.unavailable[endpoint]
}

func (h *backendHealth) count() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.unavailable)
}
