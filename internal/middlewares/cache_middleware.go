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
	"context"
	"fmt"
	"github.com/jkaninda/goma-gateway/pkg/logger"
	"net/http"
	"slices"
	"sync"
	"time"
)

type HttpCache struct {
	// Path, route path
	Path string
	// Name, route name
	Name       string
	Cache      *Cache
	RedisCache *RedisCache
	TTL        time.Duration
	// Paths, middlewares paths
	Paths                    []string
	RedisBased               bool
	DisableCacheStatusHeader bool
	ExcludedResponseCodes    []int
}

// RedisCache is a wrapper around the Redis client.
type RedisCache struct {
	ttl time.Duration
	mu  sync.RWMutex
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

// NewRedisCache initializes a Redis client and returns a RedisCache.
func NewRedisCache(ttl time.Duration) *RedisCache {
	return &RedisCache{
		ttl: ttl,
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

// Get retrieves a cached response from Redis.
func (r *RedisCache) Get(ctx context.Context, key string) ([]byte, string, bool) {
	val, err := RedisClient.HGetAll(ctx, key).Result()
	if err != nil || len(val) == 0 {
		if err != nil {
			logger.Error("Error Redis cache: %v", err)

		}
		return nil, "", false
	}
	return []byte(val["response"]), val["contentType"], true
}

// Set stores a response in Redis with an expiration time.
func (r *RedisCache) Set(ctx context.Context, key string, response []byte, contentType string) error {
	data := map[string]interface{}{
		"response":    response,
		"contentType": contentType,
	}
	err := RedisClient.HSet(ctx, key, data).Err()
	if err != nil {
		return err
	}
	return RedisClient.Expire(ctx, key, r.ttl).Err()
}

// Delete removes a cached response from the memory cache.
func (c *Cache) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	delete(c.data, key)
}

// CacheMiddleware adds caching to HTTP handlers.
func (h HttpCache) CacheMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cacheKey := fmt.Sprintf("%s-%s", h.Name, r.URL.Path)
		ctx := r.Context()

		// Check if the path is eligible for caching
		if !isPathMatching(r.URL.Path, h.Path, h.Paths) {
			next.ServeHTTP(w, r)
			return
		}

		// Only cache GET requests
		if r.Method == http.MethodGet {
			if h.RedisBased {
				if response, contentType, found := h.RedisCache.Get(ctx, cacheKey); found {
					logger.Debug("Redis: Response found in the cache")
					writeCachedResponse(w, contentType, response, h.TTL, h.DisableCacheStatusHeader)
					return
				}
			} else {
				if cachedItem, found := h.Cache.Get(cacheKey); found {
					logger.Debug("Memory: Response found in the cache")
					writeCachedResponse(w, cachedItem.ContentType, cachedItem.Response, h.TTL, h.DisableCacheStatusHeader)
					return
				}
			}
		}

		// Capture the response
		rec := &responseRecorder{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(rec, r)

		// Check if the response code is excluded from caching
		if isExcludedResponseCode(rec.statusCode, h.ExcludedResponseCodes) {
			logger.Info("Status code %d is excluded from caching", rec.statusCode)
			return
		}

		// Handle cache invalidation and caching based on the request method and response status
		if h.RedisBased {
			h.handleRedisCache(ctx, cacheKey, r, rec)
		} else {
			h.handleMemoryCache(cacheKey, r, rec)
		}
	})
}

// handleRedisCache handles Redis-based caching logic
func (h HttpCache) handleRedisCache(ctx context.Context, cacheKey string, r *http.Request, rec *responseRecorder) {
	if (r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodDelete) && (rec.statusCode >= 200 && rec.statusCode < 400) {
		h.RedisCache.mu.Lock()
		defer h.RedisCache.mu.Unlock()
		if err := RedisClient.Del(ctx, cacheKey).Err(); err != nil {
			logger.Error("Failed to invalidate cache for key %s: %v", cacheKey, err)
		}
		logger.Debug("Redis: Cache invalidated: Status: %d", rec.statusCode)
		return
	}

	if r.Method == http.MethodGet && (rec.statusCode >= 200 && rec.statusCode < 400) {
		if err := h.RedisCache.Set(ctx, cacheKey, rec.body, rec.Header().Get("Content-Type")); err != nil {
			logger.Error("Error redis cache: %v", err.Error())
			return
		}
		if !h.DisableCacheStatusHeader {
			rec.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d", int(h.TTL.Seconds())))
		}
		logger.Debug("Redis: Response saved")
	}
}

// handleMemoryCache handles in-memory caching logic
func (h HttpCache) handleMemoryCache(cacheKey string, r *http.Request, rec *responseRecorder) {
	if (r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodDelete) && (rec.statusCode >= 200 && rec.statusCode < 400) {
		h.Cache.mu.Lock()
		defer h.Cache.mu.Unlock()
		h.Cache.Delete(cacheKey)
		logger.Debug("Memory: Cache invalidated: Status: %d", rec.statusCode)
		return
	}

	if r.Method == http.MethodGet && (rec.statusCode >= 200 && rec.statusCode < 400) {
		h.Cache.Set(cacheKey, rec.body, rec.Header().Get("Content-Type"), h.TTL)
		if !h.DisableCacheStatusHeader {
			rec.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d", int(h.TTL.Seconds())))
		}
		logger.Debug("Memory: Response saved")
	}
}

// writeCachedResponse writes a cached response to the client.
func writeCachedResponse(w http.ResponseWriter, contentType string, response []byte, ttl time.Duration, disableCacheStatusHeader bool) {
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Proxied-By", "Goma Gateway")
	if !disableCacheStatusHeader {
		w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d", int(ttl.Seconds())))
	}
	_, err := w.Write(response)
	if err != nil {
		logger.Error("Failed to write cached response: %v", err)
	}
}

// isExcludedResponseCode checks if a status code is in the excluded list.
func isExcludedResponseCode(statusCode int, excludedCodes []int) bool {
	return len(excludedCodes) > 0 && slices.Contains(excludedCodes, statusCode)
}
