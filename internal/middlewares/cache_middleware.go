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

package middlewares

import (
	"fmt"
	"github.com/jkaninda/goma-gateway/pkg/logger"
	"net/http"
	"slices"
	"sync"
	"time"
)

type HttpCache struct {
	Cache                    *Cache
	TTL                      time.Duration
	DisableCacheStatusHeader bool
	ExcludedResponseCodes    []int
	MemoryLimit              string
}

// responseRecorder helps capture the response.
type responseRecorder struct {
	http.ResponseWriter
	statusCode int
	body       []byte
}

func (rec *responseRecorder) WriteHeader(statusCode int) {
	rec.statusCode = statusCode
	rec.ResponseWriter.WriteHeader(statusCode)
}

func (rec *responseRecorder) Write(data []byte) (int, error) {
	rec.body = append(rec.body, data...)
	return rec.ResponseWriter.Write(data)
}

// CacheItem represents a cached response.
type CacheItem struct {
	Response    []byte
	ContentType string
	ExpiresAt   time.Time
}

// Cache is a thread-safe in-memory cache.
type Cache struct {
	data map[string]*CacheItem
	mu   sync.RWMutex
}

// NewCache creates a new Cache.
func NewCache() *Cache {
	return &Cache{
		data: make(map[string]*CacheItem),
	}
}

// Get retrieves an item from the cache.
func (c *Cache) Get(key string) (*CacheItem, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	item, found := c.data[key]
	if found && item.ExpiresAt.After(time.Now()) {
		return item, true
	}
	return nil, false
}

// Set stores an item in the cache.
func (c *Cache) Set(key string, response []byte, contentType string, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data[key] = &CacheItem{
		Response:    response,
		ContentType: contentType,
		ExpiresAt:   time.Now().Add(ttl),
	}
}

// CacheMiddleware Middleware that adds caching to HTTP handlers.
func (h HttpCache) CacheMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cacheKey := r.URL.String()

		// Check if the response is in the cache.
		if cachedItem, found := h.Cache.Get(cacheKey); found {
			logger.Info("Response found in the cache ")
			w.Header().Set("Content-Type", cachedItem.ContentType)
			w.Header().Set("Proxied-By", "Goma Gateway")
			if !h.DisableCacheStatusHeader {
				w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d", int(h.TTL.Seconds())))
			}
			w.Write(cachedItem.Response)
			return
		}
		logger.Info("Response not found in the cache ")
		// Capture the response.
		recorder := &responseRecorder{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(recorder, r)
		if len(h.ExcludedResponseCodes) != 0 {
			if slices.Contains(h.ExcludedResponseCodes, recorder.statusCode) {
				logger.Info("Status code: %d excluded", recorder.statusCode)
				return
			}
		}
		// Cache the response.
		h.Cache.Set(cacheKey, recorder.body, recorder.Header().Get("Content-Type"), h.TTL)
		if !h.DisableCacheStatusHeader {
			w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d", int(h.TTL.Seconds())))
		}

	})
}
