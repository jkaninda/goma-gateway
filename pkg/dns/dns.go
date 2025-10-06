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

package dns

import (
	"context"
	"net"
	"sync"
	"time"
)

type dnsCacheEntry struct {
	addrs     []string
	timestamp time.Time
}

type CachedDialer struct {
	net.Dialer
	cache     map[string]dnsCacheEntry
	ttl       time.Duration
	cacheLock sync.Mutex
}

func NewCachedDialer(ttl time.Duration) *CachedDialer {
	return &CachedDialer{
		Dialer: net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		},
		cache: make(map[string]dnsCacheEntry),
		ttl:   ttl,
	}
}

func (d *CachedDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}

	d.cacheLock.Lock()
	entry, ok := d.cache[host]
	if !ok || time.Since(entry.timestamp) > d.ttl {
		ips, err := net.DefaultResolver.LookupHost(ctx, host)
		if err != nil {
			d.cacheLock.Unlock()
			return nil, err
		}
		entry = dnsCacheEntry{
			addrs:     ips,
			timestamp: time.Now(),
		}
		d.cache[host] = entry
	}
	d.cacheLock.Unlock()

	target := net.JoinHostPort(entry.addrs[0], port)
	return d.Dialer.DialContext(ctx, network, target)
}

func (d *CachedDialer) ClearCache() {
	d.cacheLock.Lock()
	defer d.cacheLock.Unlock()
	d.cache = make(map[string]dnsCacheEntry)
}
