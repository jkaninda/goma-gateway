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
	resolver  *net.Resolver
	cacheLock sync.Mutex
}

func NewCachedDialer(ttl time.Duration) *CachedDialer {
	return NewCachedDialerWithResolver(ttl, nil)
}

// NewCachedDialerWithResolver builds a CachedDialer using a custom DNS resolver.
//
// servers is a list of DNS server addresses (e.g. "1.1.1.1", "8.8.8.8:53").
// Entries without a port default to port 53. When servers is empty, the system
// default resolver (net.DefaultResolver) is used.
func NewCachedDialerWithResolver(ttl time.Duration, servers []string) *CachedDialer {
	return &CachedDialer{
		Dialer: net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		},
		cache:    make(map[string]dnsCacheEntry),
		ttl:      ttl,
		resolver: newResolver(servers),
	}
}

// newResolver returns a resolver that queries the provided DNS servers in order,
// or net.DefaultResolver when no servers are configured.
func newResolver(servers []string) *net.Resolver {
	if len(servers) == 0 {
		return net.DefaultResolver
	}

	// Normalize each server to host:port, defaulting to port 53.
	normalized := make([]string, 0, len(servers))
	for _, s := range servers {
		if s == "" {
			continue
		}
		if _, _, err := net.SplitHostPort(s); err != nil {
			s = net.JoinHostPort(s, "53")
		}
		normalized = append(normalized, s)
	}
	if len(normalized) == 0 {
		return net.DefaultResolver
	}

	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 5 * time.Second}
			var lastErr error
			for _, server := range normalized {
				conn, err := d.DialContext(ctx, network, server)
				if err == nil {
					return conn, nil
				}
				lastErr = err
			}
			return nil, lastErr
		},
	}
}

// activeResolver returns the configured resolver, falling back to the system
// default for dialers built without one.
func (d *CachedDialer) activeResolver() *net.Resolver {
	if d.resolver == nil {
		return net.DefaultResolver
	}
	return d.resolver
}

func (d *CachedDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}

	d.cacheLock.Lock()
	entry, ok := d.cache[host]
	d.cacheLock.Unlock()

	if !ok || time.Since(entry.timestamp) > d.ttl {
		ips, err := d.activeResolver().LookupHost(ctx, host)
		if err != nil {
			return nil, err
		}
		entry = dnsCacheEntry{
			addrs:     ips,
			timestamp: time.Now(),
		}
		d.cacheLock.Lock()
		d.cache[host] = entry
		d.cacheLock.Unlock()
	}

	var lastErr error
	for _, ip := range entry.addrs {
		target := net.JoinHostPort(ip, port)
		conn, err := d.Dialer.DialContext(ctx, network, target)
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	d.ClearHost(host)
	return nil, lastErr
}

func (d *CachedDialer) ClearHost(host string) {
	d.cacheLock.Lock()
	defer d.cacheLock.Unlock()
	delete(d.cache, host)
}
func (d *CachedDialer) ClearCache() {
	d.cacheLock.Lock()
	defer d.cacheLock.Unlock()
	d.cache = make(map[string]dnsCacheEntry)
}
