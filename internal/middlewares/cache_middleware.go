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
	"github.com/jkaninda/goma-gateway/util"
	"net/http"
	"slices"
	"sync"
	"time"
)

type HttpCache struct {
	// Path, route path
	Path string
	// Name, route name
	Name  string
	Cache *Cache
	TTL   time.Duration
	// Paths, middlewares paths
	Paths                    []string
	DisableCacheStatusHeader bool
	ExcludedResponseCodes    []int
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
	data        map[string]*CacheItem
	mu          sync.RWMutex
	memoryUsed  int64
	memoryLimit int64 // in bytes

}

// NewCache creates a new Cache.
func NewCache(memoryLimit int64) *Cache {
	return &Cache{
		data:        make(map[string]*CacheItem),
		memoryLimit: memoryLimit,
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
	// Calculate the size of the new cache item.
	newItemSize := int64(len(response))

	if c.memoryLimit != 0 {
		// Evict items if necessary to stay within the memory limit.
		for c.memoryUsed+newItemSize > c.memoryLimit {
			c.evictOldest()
		}
	}

	c.data[key] = &CacheItem{
		Response:    response,
		ContentType: contentType,
		ExpiresAt:   time.Now().Add(ttl),
	}
}

// evictOldest removes the oldest item in the cache to free up memory.
func (c *Cache) evictOldest() {
	var oldestKey string
	var oldestTime time.Time

	// Find the oldest item.
	for key, item := range c.data {
		if oldestKey == "" || item.ExpiresAt.Before(oldestTime) {
			oldestKey = key
			oldestTime = item.ExpiresAt
		}
	}

	// Remove the oldest item.
	if oldestKey != "" {
		c.memoryUsed -= int64(len(c.data[oldestKey].Response))
		delete(c.data, oldestKey)
	}
}

// CacheMiddleware adds caching to HTTP handlers.
func (h HttpCache) CacheMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cacheKey := fmt.Sprintf("%s-%s", h.Name, r.URL.Path)

		// Check if the path is eligible for caching
		if !isPathCacheEnabled(r.URL.Path, h.Path, h.Paths) {
			next.ServeHTTP(w, r)
			return
		}

		// Attempt to retrieve response from the cache
		if cachedItem, found := h.Cache.Get(cacheKey); found {
			logger.Info("Response found in the cache")
			writeCachedResponse(w, *cachedItem, h.TTL, h.DisableCacheStatusHeader)
			return
		}

		logger.Info("Response not found in the cache")

		// Capture the response
		recorder := &responseRecorder{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(recorder, r)

		// Check if the response code is excluded from caching
		if isExcludedResponseCode(recorder.statusCode, h.ExcludedResponseCodes) {
			logger.Info("Status code %d is excluded from caching", recorder.statusCode)
			return
		}

		// Cache the response
		h.Cache.Set(cacheKey, recorder.body, recorder.Header().Get("Content-Type"), h.TTL)
		if !h.DisableCacheStatusHeader {
			w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d", int(h.TTL.Seconds())))
		}
	})
}

// writeCachedResponse writes a cached response to the client.
func writeCachedResponse(w http.ResponseWriter, cachedItem CacheItem, ttl time.Duration, disableCacheStatusHeader bool) {
	w.Header().Set("Content-Type", cachedItem.ContentType)
	w.Header().Set("Proxied-By", "Goma Gateway")
	if !disableCacheStatusHeader {
		w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d", int(ttl.Seconds())))
	}
	_, err := w.Write(cachedItem.Response)
	if err != nil {
		logger.Error("Failed to write cached response: %v", err)
	}
}
func isPathCacheEnabled(urlPath, prefix string, paths []string) bool {
	for _, path := range paths {
		return isPathBlocked(urlPath, util.ParseURLPath(prefix+path))
	}
	return false
}

// isExcludedResponseCode checks if a status code is in the excluded list.
func isExcludedResponseCode(statusCode int, excludedCodes []int) bool {
	return len(excludedCodes) > 0 && slices.Contains(excludedCodes, statusCode)
}
