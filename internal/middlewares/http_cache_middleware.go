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
	"strconv"
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
	MaxStale   time.Duration
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

// Get retrieves an item from the cache with max-stale support.
func (c *Cache) Get(key string, maxStale time.Duration) (*CacheItem, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	item, found := c.data[key]
	if !found {
		// Cache miss: Item not found.
		return nil, false
	}

	// Get current time for expiration check.
	now := time.Now()

	// Check if the item is fresh.
	if item.ExpiresAt.After(now) {
		// Cache hit with fresh item.
		return item, true
	}

	// Item is expired, check if it's within the max-stale window.
	if maxStale > 0 && now.Before(item.ExpiresAt.Add(maxStale)) {
		// Cache hit with stale item, but within max-stale duration.
		return item, true
	}

	// Cache miss or expired beyond the max-stale period.
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

// GetTTL retrieves the remaining TTL for a given cache key.
// If the key does not exist or has expired, it returns 0 and false.
func (c *Cache) GetTTL(key string) (time.Duration, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	item, found := c.data[key]
	if !found || item.ExpiresAt.Before(time.Now()) {
		return 0, false
	}
	remainingTTL := time.Until(item.ExpiresAt)
	return remainingTTL, true
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

// Get retrieves a cached response from Redis with max-stale support.
func (r *RedisCache) Get(ctx context.Context, key string, maxStale time.Duration) ([]byte, string, bool) {
	// Fetch the entire hash for the given key.
	val, err := RedisClient.HGetAll(ctx, key).Result()
	if err != nil || len(val) == 0 {
		if err != nil {
			logger.Error("Error Redis cache: %v", err)
		}
		return nil, "", false
	}

	// Parse the required fields from the Redis hash.
	response := val["response"]
	contentType := val["contentType"]
	expiresAtStr := val["expiresAt"]

	// Validate the existence of necessary fields.
	if response == "" || contentType == "" || expiresAtStr == "" {
		logger.Error("Incomplete cache entry for key: %s", key)
		return nil, "", false
	}

	// Parse the expiration timestamp.
	expiresAt, err := strconv.ParseInt(expiresAtStr, 10, 64)
	if err != nil {
		logger.Error("Invalid expiresAt value for key: %s, error: %v", key, err)
		return nil, "", false
	}

	// Determine the current time and expiration status.
	now := time.Now().Unix()
	if now > expiresAt {
		// The item is expired; check if it falls within the max-stale period.
		if maxStale > 0 && now <= expiresAt+int64(maxStale.Seconds()) {
			// Serve the stale item within the max-stale period.
			return []byte(response), contentType, true
		}
		// Item is expired and beyond the max-stale period.
		return nil, "", false
	}

	// Item is fresh; serve it.
	return []byte(response), contentType, true
}

// Set stores a response in Redis with an expiration time.
func (r *RedisCache) Set(ctx context.Context, key string, response []byte, contentType string, ttl time.Duration) error {
	data := map[string]interface{}{
		"response":    response,
		"contentType": contentType,
		"expiresAt":   time.Now().Add(ttl).Unix(),
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
			// Parse the max-stale value from the Cache-Control header
			maxStale := parseMaxStale(r.Header.Get("Cache-Control"))
			if h.RedisBased {
				if response, contentType, found := h.RedisCache.Get(ctx, cacheKey, maxStale); found {
					// Calculate remaining TTL and set Cache-Control
					ttl, err := RedisClient.TTL(ctx, cacheKey).Result()
					if err != nil {
						http.Error(w, "Failed to get TTL", http.StatusInternalServerError)
						return
					}
					writeCachedResponse(w, contentType, response, ttl, h.DisableCacheStatusHeader)
					logger.Debug("Redis: served from cache: %s", r.URL.Path)
					return
				}
			} else {
				if cachedItem, found := h.Cache.Get(cacheKey, maxStale); found {
					// Calculate remaining TTL and set Cache-Control
					ttl, _ := h.Cache.GetTTL(cacheKey)
					writeCachedResponse(w, cachedItem.ContentType, cachedItem.Response, ttl, h.DisableCacheStatusHeader)
					logger.Debug("Memory: served from cache: %s", r.URL.Path)
					return
				}
			}
			if !h.DisableCacheStatusHeader {
				// Set Cache-Control for new response
				w.Header().Set("X-Cache-Status", "MISS") // Indicate cache miss
				w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d", int(h.TTL.Seconds())))
			}
		}
		// Capture the response
		rec := &responseRecorder{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(rec, r)

		// Check if the response code is excluded from caching
		if isExcludedResponseCode(rec.statusCode, h.ExcludedResponseCodes) {
			logger.Debug("Status code %d is excluded from caching", rec.statusCode)
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
		if err := h.RedisCache.Set(ctx, cacheKey, rec.body, rec.Header().Get("Content-Type"), h.TTL); err != nil {
			logger.Error("Error redis cache: %v", err.Error())
			return
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
		logger.Debug("Memory: Response saved")
	}
}

// writeCachedResponse writes a cached response to the client.
func writeCachedResponse(w http.ResponseWriter, contentType string, response []byte, ttl time.Duration, disableCacheStatusHeader bool) {
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Proxied-By", "Goma Gateway")
	if !disableCacheStatusHeader {
		w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d", int(ttl.Seconds())))
		w.Header().Set("X-Cache-Status", "HIT") // Indicate cache hit
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

// parseMaxStale extracts the max-stale value from the Cache-Control header
func parseMaxStale(cacheControl string) time.Duration {
	// Example Cache-Control header: "max-stale=60"
	if cacheControl == "" {
		return 0
	}

	var maxStale int
	_, err := fmt.Sscanf(cacheControl, "max-stale=%d", &maxStale)
	if err != nil {
		return 0 // No max-stale directive or invalid value
	}

	return time.Duration(maxStale) * time.Second
}
