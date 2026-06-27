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
	"net"
	"testing"
	"time"
)

func TestNewCachedDialerWithoutResolverUsesDefault(t *testing.T) {
	d := NewCachedDialer(time.Minute)
	if d.activeResolver() != net.DefaultResolver {
		t.Fatal("expected default resolver when none configured")
	}
}

func TestNewCachedDialerWithResolverEmptyFallsBack(t *testing.T) {
	d := NewCachedDialerWithResolver(time.Minute, nil)
	if d.activeResolver() != net.DefaultResolver {
		t.Fatal("expected default resolver for empty server list")
	}
	d = NewCachedDialerWithResolver(time.Minute, []string{"", ""})
	if d.activeResolver() != net.DefaultResolver {
		t.Fatal("expected default resolver when all entries are empty")
	}
}

func TestNewCachedDialerWithResolverCustom(t *testing.T) {
	d := NewCachedDialerWithResolver(time.Minute, []string{"1.1.1.1", "8.8.8.8:53"})
	if d.activeResolver() == net.DefaultResolver {
		t.Fatal("expected a custom resolver")
	}
	if !d.resolver.PreferGo {
		t.Fatal("expected custom resolver to PreferGo")
	}
}

func TestClearCache(t *testing.T) {
	d := NewCachedDialer(time.Minute)
	d.cache["example.com"] = dnsCacheEntry{addrs: []string{"127.0.0.1"}, timestamp: time.Now()}
	d.ClearCache()
	if len(d.cache) != 0 {
		t.Fatalf("expected empty cache after ClearCache, got %d entries", len(d.cache))
	}
}

func TestClearHost(t *testing.T) {
	d := NewCachedDialer(time.Minute)
	d.cache["a.example"] = dnsCacheEntry{addrs: []string{"127.0.0.1"}, timestamp: time.Now()}
	d.cache["b.example"] = dnsCacheEntry{addrs: []string{"127.0.0.2"}, timestamp: time.Now()}
	d.ClearHost("a.example")
	if _, ok := d.cache["a.example"]; ok {
		t.Fatal("expected a.example to be cleared")
	}
	if _, ok := d.cache["b.example"]; !ok {
		t.Fatal("expected b.example to remain")
	}
}
