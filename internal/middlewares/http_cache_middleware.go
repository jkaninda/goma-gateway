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
	"net/url"
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
	CacheableStatusCodes     []int
	IncludeQueryInKey        bool
	QueryParamsToCache       []string
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
	Response        []byte
	ContentType     string
	ContentEncoding string
	Size            int64 // Size of the item in memory
	ExpiresAt       time.Time
}

// GetTTL retrieves the remaining TTL for a given cache key.
// If the key does not exist or has expired, it returns 0 and false.
func (c *Cache) GetTTL(ctx context.Context, key string) time.Duration {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.redisBased && RedisClient != nil {
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
	if c.redisBased && RedisClient != nil {
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
func (c *Cache) Get(ctx context.Context, key string, maxStale time.Duration) ([]byte, string, string, time.Duration, bool) {
	ttl := c.GetTTL(ctx, key)
	if c.redisBased && RedisClient != nil {
		val, err := RedisClient.HGetAll(ctx, key).Result()
		if errors.Is(err, redis.Nil) {
			return nil, "", "", time.Duration(0), false
		} else if err != nil {
			logger.Error("Error retrieving item from Redis", "error", err)
			return nil, "", "", time.Duration(0), false
		}

		response := val["response"]
		contentType := val["contentType"]
		contentEncoding := val["contentEncoding"]
		expiresAtStr := val["expiresAt"]

		if response == "" || contentType == "" || expiresAtStr == "" {
			logger.Debug("Cache entry missing data for key", "key", key)
			return nil, "", "", time.Duration(0), false
		}

		expiresAt, err := strconv.ParseInt(expiresAtStr, 10, 64)
		if err != nil {
			logger.Debug("Invalid cache, cache expired", "key", key, "error", err)
			return nil, "", "", time.Duration(0), false
		}

		now := time.Now()
		if now.After(time.Unix(expiresAt, 0)) {
			if maxStale > 0 && now.Before(time.Unix(expiresAt, 0).Add(maxStale)) {
				return []byte(response), contentType, contentEncoding, ttl, true
			}
			return nil, "", "", ttl, false
		}
		return []byte(response), contentType, contentEncoding, ttl, true
	}

	// In-memory cache
	c.mu.RLock()
	item, found := c.data[key]
	c.mu.RUnlock()
	if found {
		now := time.Now()
		if item.ExpiresAt.After(now) {
			return item.Response, item.ContentType, item.ContentEncoding, ttl, true
		}
		if maxStale > 0 && now.Before(item.ExpiresAt.Add(maxStale)) {
			return item.Response, item.ContentType, item.ContentEncoding, ttl, true
		}
	}
	return nil, "", "", ttl, false
}

// Set stores an item in both Redis and the in-memory cache with memory limit checks.
func (c *Cache) Set(ctx context.Context, key string, response []byte, contentType, contentEncoding string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.redisBased {
		data := map[string]interface{}{
			"response":        response,
			"contentType":     contentType,
			"contentEncoding": contentEncoding,
			"expiresAt":       time.Now().Add(c.ttl).Unix(),
		}
		err := RedisClient.HSet(ctx, key, data).Err()
		if err != nil {
			return err
		}
		logger.Debug("In redis: Response saved")
		return RedisClient.Expire(ctx, key, c.ttl).Err()
	}

	itemSize := int64(len(response))
	for c.memoryUsed+itemSize > c.memoryLimit {
		c.evictOldest()
	}

	item := &CacheItem{
		Response:        response,
		ContentType:     contentType,
		ContentEncoding: contentEncoding,
		Size:            itemSize,
		ExpiresAt:       time.Now().Add(c.ttl),
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
	if c.redisBased && RedisClient != nil {
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
		ctx := r.Context()

		if !isPathMatching(r.URL.Path, h.Path, h.Paths) {
			next.ServeHTTP(w, r)
			return
		}

		// Generate cache key
		cacheKey := h.generateCacheKey(r)

		if r.Method == http.MethodGet {
			maxStale := parseMaxStale(r.Header.Get("Cache-Control"))
			if response, contentType, contentEncoding, ttl, found := h.Cache.Get(ctx, cacheKey, maxStale); found {
				if allowedOrigin(h.Origins, r.Header.Get("Origin")) {
					w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
				}
				writeCachedResponse(w, contentType, contentEncoding, response, ttl, h.DisableCacheStatusHeader)
				logger.Debug("Cache: served from cache", "key", cacheKey)
				return
			}
			w.Header().Set(constGomaCacheHeader, "MISS")
			w.Header().Set(constGomaCacheMaxAgeHeader, fmt.Sprintf("%d", int(h.TTL.Seconds())))
			if !h.DisableCacheStatusHeader {
				w.Header().Set("X-Cache-Status", "MISS")
				w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%v", h.TTL.Seconds()))
			}
		}

		rec := &responseRecorder{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(rec, r)

		if !h.shouldCacheStatus(rec.statusCode) {
			logger.Debug("Status code excluded from caching", "status", rec.statusCode)
			return
		}

		h.handleCache(ctx, cacheKey, r, rec)
	})
}

// handleCache handles caching logic
func (h HttpCacheConfig) handleCache(ctx context.Context, cacheKey string, r *http.Request, rec *responseRecorder) {
	if (r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodDelete) && (rec.statusCode >= 200 && rec.statusCode < 400) {
		if err := h.Cache.Delete(ctx, cacheKey); err != nil {
			logger.Error("Failed to invalidate cache", "key", cacheKey, "error", err)
		}
		logger.Debug("Cache invalidated", "status", rec.statusCode)
		return
	}

	if r.Method == http.MethodGet && (rec.statusCode >= 200 && rec.statusCode < 400) {
		contentType := rec.Header().Get("Content-Type")
		contentEncoding := rec.Header().Get("Content-Encoding")

		if err := h.Cache.Set(ctx, cacheKey, rec.body, contentType, contentEncoding); err != nil {
			logger.Error("Error saving response in cache", "error", err.Error())
			return
		}
	}
}

// writeCachedResponse writes a cached response to the client.
func writeCachedResponse(w http.ResponseWriter, contentType, contentEncoding string, response []byte, ttl time.Duration, disableCacheStatusHeader bool) {
	w.Header().Set("Content-Type", contentType)
	w.Header().Set(constGomaCacheHeader, "HIT")
	w.Header().Set(constGomaCacheMaxAgeHeader, fmt.Sprintf("%d", int(ttl.Seconds())))
	if contentEncoding != "" {
		w.Header().Set("Content-Encoding", contentEncoding)
	}
	if !disableCacheStatusHeader {
		w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d", int(ttl.Seconds())))
		w.Header().Set("X-Cache-Status", "HIT")
	}

	_, err := w.Write(response)
	if err != nil {
		logger.Error("Failed to write cached response", "error", err)
	}
}

// parseMaxStale extracts the max-stale value from the Cache-Control header
func parseMaxStale(cacheControl string) time.Duration {
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
func (h HttpCacheConfig) shouldCacheStatus(statusCode int) bool {
	if len(h.CacheableStatusCodes) > 0 {
		return slices.Contains(h.CacheableStatusCodes, statusCode)
	}

	excludedCodes := h.getExcludedStatusCodes()
	return !slices.Contains(excludedCodes, statusCode)
}

// generateCacheKey creates a cache key with optional query parameter filtering
func (h HttpCacheConfig) generateCacheKey(r *http.Request) string {
	baseKey := fmt.Sprintf("%s-%s", h.Name, r.URL.Path)

	if !h.IncludeQueryInKey {
		return baseKey
	}

	query := r.URL.Query()

	if len(h.QueryParamsToCache) == 0 {
		queryString := query.Encode()
		if queryString == "" {
			return baseKey
		}
		return fmt.Sprintf("%s?%s", baseKey, queryString)
	}

	filteredQuery := url.Values{}
	for _, param := range h.QueryParamsToCache {
		if values, exists := query[param]; exists {
			filteredQuery[param] = values
		}
	}

	if len(filteredQuery) == 0 {
		return baseKey
	}

	queryString := filteredQuery.Encode()
	return fmt.Sprintf("%s?%s", baseKey, queryString)
}

// getExcludedStatusCodes returns the list of status codes to exclude from caching
func (h HttpCacheConfig) getExcludedStatusCodes() []int {
	if len(h.ExcludedResponseCodes) > 0 {
		return h.ExcludedResponseCodes
	}

	return []int{
		// Client errors
		http.StatusBadRequest,       // 400
		http.StatusUnauthorized,     // 401
		http.StatusPaymentRequired,  // 402
		http.StatusForbidden,        // 403
		http.StatusNotFound,         // 404
		http.StatusMethodNotAllowed, // 405
		http.StatusConflict,         // 409
		http.StatusGone,             // 410
		http.StatusTooManyRequests,  // 429

		// Server errors
		http.StatusInternalServerError, // 500
		http.StatusNotImplemented,      // 501
		http.StatusBadGateway,          // 502
		http.StatusServiceUnavailable,  // 503
		http.StatusGatewayTimeout,      // 504

		http.StatusMovedPermanently,  // 301
		http.StatusFound,             // 302
		http.StatusTemporaryRedirect, // 307
		http.StatusPermanentRedirect, // 308
	}
}
