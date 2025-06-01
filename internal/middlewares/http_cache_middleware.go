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
	"errors"
	"fmt"
	"github.com/redis/go-redis/v9"
	"net/http"
	"slices"
	"strconv"
	"sync"
	"time"
)

type HttpCacheConfig struct {
	// Path, route path
	Path string
	// Name, route name
	Name     string
	Cache    *Cache
	TTL      time.Duration
	MaxStale time.Duration
	// Paths, middlewares paths
	Paths                    []string
	Origins                  []string
	RedisBased               bool
	DisableCacheStatusHeader bool
	ExcludedResponseCodes    []int
}

// Cache is a wrapper around the Redis client.
type Cache struct {
	ttl         time.Duration
	data        map[string]*CacheItem
	redisBased  bool
	memoryLimit int64
	memoryUsed  int64
	mu          sync.RWMutex
}

// responseRecorder helps capture the response.
type responseRecorder struct {
	http.ResponseWriter
	statusCode int
	body       []byte
}

// HttpCache defines the interface for a cache.
type HttpCache interface {
	Get(ctx context.Context, key string, maxStale time.Duration) ([]byte, string, time.Duration, bool)
	Set(ctx context.Context, key string, response []byte, contentType string) error
	Delete(ctx context.Context, key string) error
	GetTTL(ctx context.Context, key string) time.Duration
}

// NewHttpCacheMiddleware creates new HTTP cache middleware.
func NewHttpCacheMiddleware(redisBased bool, ttl time.Duration, memoryLimit int64) *Cache {
	return &Cache{
		ttl:         ttl,
		redisBased:  redisBased,
		data:        make(map[string]*CacheItem),
		memoryLimit: memoryLimit,
	}
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
	Size        int64 // Size of the item in memory
	ExpiresAt   time.Time
}

// GetTTL retrieves the remaining TTL for a given cache key.
// If the key does not exist or has expired, it returns 0 and false.
func (c *Cache) GetTTL(ctx context.Context, key string) time.Duration {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.redisBased {
		ttl, err := RedisClient.TTL(ctx, key).Result()
		if err != nil {
			logger.Error("Failed to get TTL", "error", err)
			return 0
		}
		return ttl
	}
	item, found := c.data[key]
	if !found || item.ExpiresAt.Before(time.Now()) {
		return 0
	}
	remainingTTL := time.Until(item.ExpiresAt)

	return remainingTTL
}

// evictOldest evicts the oldest item in the cache to make room for new items.
func (c *Cache) evictOldest() {
	var oldestKey string
	var oldestTime time.Time
	if c.redisBased {
		// Remove from Redis.
		RedisClient.Del(context.Background(), oldestKey)
		logger.Debug("Evicted item", "key", oldestKey)
		return
	}

	for key, item := range c.data {
		if oldestTime.IsZero() || item.ExpiresAt.Before(oldestTime) {
			oldestKey = key
			oldestTime = item.ExpiresAt
		}
	}

	// Evict the oldest item from memory.
	if oldestKey != "" {
		c.mu.Lock()
		defer c.mu.Unlock()

		// Remove from memory.
		item := c.data[oldestKey]
		delete(c.data, oldestKey)
		c.memoryUsed -= item.Size

	}

}

// Get retrieves an item from Redis or the in-memory cache with max-stale support.
func (c *Cache) Get(ctx context.Context, key string, maxStale time.Duration) ([]byte, string, time.Duration, bool) {
	ttl := c.GetTTL(ctx, key)
	if c.redisBased {
		//  check Redis.
		val, err := RedisClient.HGetAll(ctx, key).Result()
		if errors.Is(err, redis.Nil) {
			// Key does not exist in Redis.
			return nil, "", time.Duration(0), false
		} else if err != nil {
			// Redis error.
			logger.Error("Error retrieving item from Redis", "error", err)
			return nil, "", time.Duration(0), false
		}
		// The item was found in Redis, retrieve the response and contentType.
		response := val["response"]
		contentType := val["contentType"]
		expiresAtStr := val["expiresAt"]

		// If any of the necessary fields are missing, return a cache miss.
		if response == "" || contentType == "" || expiresAtStr == "" {
			logger.Debug("Cache entry missing data for key", "key", key)
			return nil, "", time.Duration(0), false
		}

		// Parse the expiration timestamp.
		expiresAt, err := strconv.ParseInt(expiresAtStr, 10, 64)
		if err != nil {
			logger.Debug("Invalid cache, cache expired", "key", key, "error", err)
			return nil, "", time.Duration(0), false
		}

		// Check expiration and max-stale.
		now := time.Now()
		if now.After(time.Unix(expiresAt, 0)) {
			// Item is expired, check if within max-stale window.
			if maxStale > 0 && now.Before(time.Unix(expiresAt, 0).Add(maxStale)) {
				return []byte(response), contentType, ttl, true
			}
			// Item expired and beyond max-stale period.
			return nil, "", ttl, false
		}
		// Item is fresh.
		return []byte(response), contentType, ttl, true

	}
	// check the in-memory cache.
	c.mu.RLock()
	item, found := c.data[key]
	c.mu.RUnlock()
	if found {
		now := time.Now()
		if item.ExpiresAt.After(now) {
			return item.Response, item.ContentType, ttl, true
		}

		// If expired, check if max-stale allows serving the stale item.
		if maxStale > 0 && now.Before(item.ExpiresAt.Add(maxStale)) {
			return item.Response, item.ContentType, ttl, true
		}
	}
	return nil, "", ttl, false
}

// Set stores an item in both Redis and the in-memory cache with memory limit checks.
func (c *Cache) Set(ctx context.Context, key string, response []byte, contentType string) error {
	itemSize := int64(len(response))
	// Check if the item will exceed the memory limit.
	c.mu.Lock()
	defer c.mu.Unlock()

	// Evict items if necessary to stay within the memory limit.
	for c.memoryUsed+itemSize > c.memoryLimit {
		c.evictOldest()
	}
	// Add the new item to the in-memory cache.
	item := &CacheItem{
		Response:    response,
		ContentType: contentType,
		Size:        itemSize,
		ExpiresAt:   time.Now().Add(c.ttl),
	}

	if c.redisBased {
		// Store the item in Redis as a hash with response and contentType.
		data := map[string]interface{}{
			"response":    response,
			"contentType": contentType,
			"expiresAt":   time.Now().Add(c.ttl).Unix(),
		}
		err := RedisClient.HSet(ctx, key, data).Err()
		if err != nil {
			return err
		}
		logger.Debug("In redis: Response saved")
		return RedisClient.Expire(ctx, key, c.ttl).Err()
	}

	c.data[key] = item
	c.memoryUsed += itemSize
	logger.Debug("In memory: Response saved")
	return nil
}

// Delete removes a cached response from the memory cache or Redis cache.
func (c *Cache) Delete(ctx context.Context, key string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.redisBased {
		if err := RedisClient.Del(ctx, key).Err(); err != nil {
			return err
		}
		return nil
	}
	delete(c.data, key)

	return nil
}

// Middleware returns the middleware function.
func (h HttpCacheConfig) Middleware(next http.Handler) http.Handler {
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
			if response, contentType, ttl, found := h.Cache.Get(ctx, cacheKey, maxStale); found {
				if allowedOrigin(h.Origins, r.Header.Get("Origin")) {
					w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
				}
				writeCachedResponse(w, contentType, response, ttl, h.DisableCacheStatusHeader)
				logger.Debug("Cache: served from cache", "path", r.URL.Path)
				return
			}
			if !h.DisableCacheStatusHeader {
				// Set Cache-Control for new response
				w.Header().Set("X-Cache-Status", "MISS") // Indicate cache miss
				w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%v", h.TTL.Seconds()))
			}
		}

		// Capture the response
		rec := &responseRecorder{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(rec, r)

		// Check if the response code is excluded from caching
		if isExcludedResponseCode(rec.statusCode, h.ExcludedResponseCodes) {
			logger.Debug("Status code excluded from caching", "status", rec.statusCode)
			return
		}
		// Handle cache invalidation and caching based on the request method and response status
		h.handleCache(ctx, cacheKey, r, rec)
	})
}

// handleCache handles Redis-based caching logic
func (h HttpCacheConfig) handleCache(ctx context.Context, cacheKey string, r *http.Request, rec *responseRecorder) {
	if (r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodDelete) && (rec.statusCode >= 200 && rec.statusCode < 400) {
		if err := h.Cache.Delete(ctx, cacheKey); err != nil {
			logger.Error("Failed to invalidate cache", "key", cacheKey, "error", err)
		}
		logger.Debug("Cache invalidated", "status", rec.statusCode)
		return
	}

	if r.Method == http.MethodGet && (rec.statusCode >= 200 && rec.statusCode < 400) {
		if err := h.Cache.Set(ctx, cacheKey, rec.body, rec.Header().Get("Content-Type")); err != nil {
			logger.Error("Error saving response in cache", "error", err.Error())
			return
		}
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
		logger.Error("Failed to write cached response", "error", err)
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
