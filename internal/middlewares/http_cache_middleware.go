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
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

const maxVaryFields = 3

var credentialHeaders = []string{"authorization", "proxy-authorization", "cookie"}

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
	CachePrivateResponses    bool
	IgnoreVary               []string
}

// Cache is a wrapper around the Redis client.
type Cache struct {
	ttl         time.Duration
	data        map[string]*CacheItem
	redisBased  bool
	memoryLimit int64
	memoryUsed  int64
	mu          sync.RWMutex
	varyHints   sync.Map

	loggedReasons sync.Map
}

// responseRecorder helps capture the response.
type responseRecorder struct {
	http.ResponseWriter
	statusCode  int
	body        []byte
	wroteHeader bool

	evaluated  bool
	storable   bool
	reason     string
	varyFields []string
	onHeader   func()
}

// CacheEntry is a stored response on its way back to a caller.
type CacheEntry struct {
	Response        []byte
	ContentType     string
	ContentEncoding string
	Vary            string
	TTL             time.Duration
}

// HttpCache defines the interface for a cache.
type HttpCache interface {
	Get(ctx context.Context, key string, maxStale time.Duration) (*CacheEntry, bool)
	Set(ctx context.Context, key string, entry *CacheEntry) error
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
	if rec.wroteHeader {
		return
	}
	rec.statusCode = statusCode

	if rec.onHeader != nil {
		rec.onHeader()
	}
	rec.wroteHeader = true
	rec.ResponseWriter.WriteHeader(statusCode)
}

func (rec *responseRecorder) Write(data []byte) (int, error) {

	if !rec.wroteHeader {
		rec.WriteHeader(http.StatusOK)
	}
	rec.body = append(rec.body, data...)
	return rec.ResponseWriter.Write(data)
}

// CacheItem represents a cached response.
type CacheItem struct {
	Response        []byte
	ContentType     string
	ContentEncoding string
	Vary            string
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

func (c *Cache) evictOldestLocked() bool {
	if c.redisBased && RedisClient != nil {
		// Redis expires entries on its own.
		return false
	}

	var oldestKey string
	var oldestTime time.Time
	for key, item := range c.data {
		if oldestTime.IsZero() || item.ExpiresAt.Before(oldestTime) {
			oldestKey = key
			oldestTime = item.ExpiresAt
		}
	}

	if oldestKey == "" {
		return false
	}

	item := c.data[oldestKey]
	delete(c.data, oldestKey)
	c.memoryUsed -= item.Size
	logger.Debug("Evicted item", "key", oldestKey)
	return true
}

// Get retrieves an item from Redis or the in-memory cache with max-stale support.
func (c *Cache) Get(ctx context.Context, key string, maxStale time.Duration) (*CacheEntry, bool) {
	ttl := c.GetTTL(ctx, key)
	if c.redisBased && RedisClient != nil {
		val, err := RedisClient.HGetAll(ctx, key).Result()
		if errors.Is(err, redis.Nil) {
			return nil, false
		} else if err != nil {
			logger.Error("Error retrieving item from Redis", "error", err)
			return nil, false
		}

		response := val["response"]
		contentType := val["contentType"]
		expiresAtStr := val["expiresAt"]

		if response == "" || contentType == "" || expiresAtStr == "" {
			logger.Debug("Cache entry missing data for key", "key", key)
			return nil, false
		}

		expiresAt, err := strconv.ParseInt(expiresAtStr, 10, 64)
		if err != nil {
			logger.Debug("Invalid cache, cache expired", "key", key, "error", err)
			return nil, false
		}

		entry := &CacheEntry{
			Response:        []byte(response),
			ContentType:     contentType,
			ContentEncoding: val["contentEncoding"],
			Vary:            val["vary"],
			TTL:             ttl,
		}

		now := time.Now()
		if now.After(time.Unix(expiresAt, 0)) {
			if maxStale > 0 && now.Before(time.Unix(expiresAt, 0).Add(maxStale)) {
				return entry, true
			}
			return nil, false
		}
		return entry, true
	}

	// In-memory cache
	c.mu.RLock()
	item, found := c.data[key]
	c.mu.RUnlock()
	if !found {
		return nil, false
	}

	now := time.Now()
	if item.ExpiresAt.After(now) || (maxStale > 0 && now.Before(item.ExpiresAt.Add(maxStale))) {
		return &CacheEntry{
			Response:        item.Response,
			ContentType:     item.ContentType,
			ContentEncoding: item.ContentEncoding,
			Vary:            item.Vary,
			TTL:             ttl,
		}, true
	}
	return nil, false
}

// Set stores an item in both Redis and the in-memory cache with memory limit checks.
func (c *Cache) Set(ctx context.Context, key string, entry *CacheEntry) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.redisBased {
		data := map[string]interface{}{
			"response":        entry.Response,
			"contentType":     entry.ContentType,
			"contentEncoding": entry.ContentEncoding,
			"vary":            entry.Vary,
			"expiresAt":       time.Now().Add(c.ttl).Unix(),
		}
		err := RedisClient.HSet(ctx, key, data).Err()
		if err != nil {
			return err
		}
		logger.Debug("In redis: Response saved")
		return RedisClient.Expire(ctx, key, c.ttl).Err()
	}

	itemSize := int64(len(entry.Response))
	for c.memoryUsed+itemSize > c.memoryLimit {
		if !c.evictOldestLocked() {
			break
		}
	}
	if itemSize > c.memoryLimit {
		logger.Debug("Response larger than the cache memory limit, not stored",
			"size", itemSize, "memoryLimit", c.memoryLimit)
		return nil
	}

	item := &CacheItem{
		Response:        entry.Response,
		ContentType:     entry.ContentType,
		ContentEncoding: entry.ContentEncoding,
		Vary:            entry.Vary,
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
	if item, found := c.data[key]; found {
		c.memoryUsed -= item.Size
		delete(c.data, key)
	}

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

		if h.isCredentialed(r) && !h.CachePrivateResponses {
			logger.Debug("Cache: bypassed for a credentialed request", "path", r.URL.Path)
			w.Header().Set(constGomaCacheHeader, "BYPASS")
			if !h.DisableCacheStatusHeader {
				w.Header().Set("X-Cache-Status", "BYPASS")
				w.Header().Set(constGomaCacheReasonHeader, "the request carried credentials")
			}
			next.ServeHTTP(w, r)
			return
		}

		baseKey := h.generateCacheKey(r)

		if r.Method == http.MethodGet {
			maxStale := parseMaxStale(r.Header.Get("Cache-Control"))
			if entry, found := h.lookup(ctx, baseKey, r, maxStale); found {
				if allowedOrigin(h.Origins, r.Header.Get("Origin")) {
					w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
					w.Header().Add("Vary", "Origin")
				}
				writeCachedResponse(w, entry, h.DisableCacheStatusHeader, h.cacheability(r))
				logger.Debug("Cache: served from cache", "key", baseKey)
				return
			}
			w.Header().Set(constGomaCacheHeader, "MISS")
			w.Header().Set(constGomaCacheMaxAgeHeader, fmt.Sprintf("%d", int(h.TTL.Seconds())))
			if !h.DisableCacheStatusHeader {
				w.Header().Set("X-Cache-Status", "MISS")
			}

		}

		rec := &responseRecorder{ResponseWriter: w, statusCode: http.StatusOK}
		rec.onHeader = func() { h.evaluate(rec, r) }
		next.ServeHTTP(rec, r)
		if !rec.evaluated {
			h.evaluate(rec, r)
		}

		h.handleCache(ctx, baseKey, r, rec)
	})
}

func (h HttpCacheConfig) lookup(ctx context.Context, baseKey string, r *http.Request, maxStale time.Duration) (*CacheEntry, bool) {
	if fields, ok := h.varyHint(baseKey); ok {
		if entry, found := h.Cache.Get(ctx, varyKey(baseKey, r, fields), maxStale); found {
			return entry, true
		}
	}
	return h.Cache.Get(ctx, baseKey, maxStale)
}

func (h HttpCacheConfig) evaluate(rec *responseRecorder, r *http.Request) {
	rec.evaluated = true
	if r.Method != http.MethodGet {
		return
	}

	rec.varyFields, rec.reason, rec.storable = h.storability(rec.Header(), rec.statusCode)

	if !rec.wroteHeader {
		if rec.storable {
			if !h.DisableCacheStatusHeader {
				rec.Header().Set("Cache-Control",
					fmt.Sprintf("%s, max-age=%d", h.cacheability(r), int(h.TTL.Seconds())))
			}
		} else {
			rec.Header().Set(constGomaCacheHeader, "BYPASS")
			rec.Header().Del(constGomaCacheMaxAgeHeader)
			if !h.DisableCacheStatusHeader {
				rec.Header().Set("X-Cache-Status", "BYPASS")
				rec.Header().Set(constGomaCacheReasonHeader, rec.reason)
			}
		}
	}

	if !rec.storable {
		h.logNotStored(r, rec.reason)
	}
}

func (h HttpCacheConfig) logNotStored(r *http.Request, reason string) {
	if h.Cache != nil {
		if _, seen := h.Cache.loggedReasons.LoadOrStore(h.Name+"|"+reason, struct{}{}); seen {
			logger.Debug("Cache: response not stored", "route", h.Name, "path", r.URL.Path, "reason", reason)
			return
		}
	}
	logger.Info("Cache: response not stored", "route", h.Name, "path", r.URL.Path, "reason", reason)
}

// handleCache handles caching logic
func (h HttpCacheConfig) handleCache(ctx context.Context, baseKey string, r *http.Request, rec *responseRecorder) {
	if (r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodDelete) && (rec.statusCode >= 200 && rec.statusCode < 400) {

		keys := []string{baseKey}
		if fields, ok := h.varyHint(baseKey); ok {
			keys = append(keys, varyKey(baseKey, r, fields))
		}
		for _, key := range keys {
			if err := h.Cache.Delete(ctx, key); err != nil {
				logger.Error("Failed to invalidate cache", "key", key, "error", err)
			}
		}
		logger.Debug("Cache invalidated", "status", rec.statusCode)
		return
	}

	if r.Method != http.MethodGet || !rec.storable {
		return
	}

	h.rememberVary(baseKey, rec.varyFields)
	entry := &CacheEntry{
		Response:        rec.body,
		ContentType:     rec.Header().Get("Content-Type"),
		ContentEncoding: rec.Header().Get("Content-Encoding"),
		Vary:            strings.Join(rec.varyFields, ", "),
	}
	if err := h.Cache.Set(ctx, varyKey(baseKey, r, rec.varyFields), entry); err != nil {
		logger.Error("Error saving response in cache", "error", err.Error())
	}
}

// writeCachedResponse writes a cached response to the client.
func writeCachedResponse(w http.ResponseWriter, entry *CacheEntry, disableCacheStatusHeader bool, cacheability string) {
	w.Header().Set("Content-Type", entry.ContentType)
	w.Header().Set(constGomaCacheHeader, "HIT")
	w.Header().Set(constGomaCacheMaxAgeHeader, fmt.Sprintf("%d", int(entry.TTL.Seconds())))
	if entry.ContentEncoding != "" {
		w.Header().Set("Content-Encoding", entry.ContentEncoding)
	}

	if entry.Vary != "" {
		w.Header().Add("Vary", entry.Vary)
	}
	if !disableCacheStatusHeader {
		w.Header().Set("Cache-Control", fmt.Sprintf("%s, max-age=%d", cacheability, int(entry.TTL.Seconds())))
		w.Header().Set("X-Cache-Status", "HIT")
	}

	_, err := w.Write(entry.Response)
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
		return 0
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

// isCredentialed reports whether the request carries anything that makes the
// response specific to its sender.
func (h HttpCacheConfig) isCredentialed(r *http.Request) bool {
	return r.Header.Get("Authorization") != "" ||
		r.Header.Get("Proxy-Authorization") != "" ||
		r.Header.Get("Cookie") != ""
}

func (h HttpCacheConfig) cacheability(r *http.Request) string {
	if h.isCredentialed(r) {
		return "private"
	}
	return "public"
}

func (h HttpCacheConfig) storability(header http.Header, status int) ([]string, string, bool) {
	if !h.shouldCacheStatus(status) {
		return nil, fmt.Sprintf("status %d is excluded from caching", status), false
	}

	if len(h.CacheableStatusCodes) == 0 && (status < 200 || status >= 400) {
		return nil, fmt.Sprintf("status %d is not a cacheable result", status), false
	}
	if header.Get("Set-Cookie") != "" {
		return nil, "the response sets a cookie", false
	}
	if header.Get("WWW-Authenticate") != "" {
		return nil, "the response is an authentication challenge", false
	}

	for _, directive := range cacheControlDirectives(header) {
		switch directive {
		case "private", "no-store", "no-cache":
			return nil, "the response is marked " + directive, false
		}
	}

	return h.varyFields(header)
}

// cacheControlDirectives splits Cache-Control into bare directive names, so
// "no-store" is recognised while "stale-while-revalidate=60" is not mistaken
// for one by a substring match.
func cacheControlDirectives(header http.Header) []string {
	var directives []string
	for _, value := range header.Values("Cache-Control") {
		for _, part := range strings.Split(value, ",") {
			name, _, _ := strings.Cut(part, "=")
			name = strings.ToLower(strings.TrimSpace(name))
			if name != "" {
				directives = append(directives, name)
			}
		}
	}
	return directives
}

func (h HttpCacheConfig) varyFields(header http.Header) ([]string, string, bool) {
	var fields []string
	for _, value := range header.Values("Vary") {
		for _, part := range strings.Split(value, ",") {
			field := strings.ToLower(strings.TrimSpace(part))
			switch {
			case field == "":
				continue
			case field == "*":
				return nil, "the response varies on everything", false
			case field == "accept-encoding":
				continue
			case slices.Contains(credentialHeaders, field):
				continue
			case h.ignoresVary(field):
				continue
			case slices.Contains(fields, field):
				continue
			}
			fields = append(fields, field)
		}
	}

	if len(fields) > maxVaryFields {
		return nil, fmt.Sprintf("the response varies on %d headers, more than the %d this cache keys on",
			len(fields), maxVaryFields), false
	}

	slices.Sort(fields)
	return fields, "", true
}

// ignoresVary reports whether the operator asked for this Vary field to be
// disregarded.
func (h HttpCacheConfig) ignoresVary(field string) bool {
	for _, ignored := range h.IgnoreVary {
		if strings.EqualFold(strings.TrimSpace(ignored), field) {
			return true
		}
	}
	return false
}

// varyHint returns the request headers the last stored response for this base
// key depended on.
func (h HttpCacheConfig) varyHint(baseKey string) ([]string, bool) {
	if h.Cache == nil {
		return nil, false
	}
	fields, ok := h.Cache.varyHints.Load(baseKey)
	if !ok {
		return nil, false
	}
	return fields.([]string), true
}

// rememberVary records what the response just stored depended on, so the next
// request can rebuild the same key.
func (h HttpCacheConfig) rememberVary(baseKey string, fields []string) {
	if h.Cache == nil {
		return
	}
	if len(fields) == 0 {
		h.Cache.varyHints.Delete(baseKey)
		return
	}
	h.Cache.varyHints.Store(baseKey, fields)
}

// varyKey extends a base key with this request's values for the headers the
// stored response depends on
func varyKey(baseKey string, r *http.Request, fields []string) string {
	if len(fields) == 0 {
		return baseKey
	}
	sum := sha256.New()
	for _, field := range fields {
		sum.Write([]byte(field))
		sum.Write([]byte{0})
		sum.Write([]byte(r.Header.Get(field)))
		sum.Write([]byte{0})
	}
	return fmt.Sprintf("%s-vary-%s", baseKey, hex.EncodeToString(sum.Sum(nil)))
}

// generateCacheKey creates a cache key with optional query parameter filtering
func (h HttpCacheConfig) generateCacheKey(r *http.Request) string {
	// The host separates routes served for several names, and the encoding
	// separates the compressed and uncompressed forms of the same body, which
	// are replayed with the Content-Encoding they were stored with.
	baseKey := fmt.Sprintf("%s-%s-%s-%s", h.Name, r.Host, acceptedEncoding(r), r.URL.Path)

	if h.CachePrivateResponses {
		baseKey = fmt.Sprintf("%s-%s", baseKey, credentialFingerprint(r))
	}

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

// acceptedEncoding reduces Accept-Encoding to the part that changes the stored
// body, so every header permutation does not become its own cache entry.
func acceptedEncoding(r *http.Request) string {
	accepted := strings.ToLower(r.Header.Get("Accept-Encoding"))
	switch {
	case strings.Contains(accepted, "br"):
		return "br"
	case strings.Contains(accepted, "gzip"):
		return "gzip"
	case strings.Contains(accepted, "deflate"):
		return "deflate"
	default:
		return "identity"
	}
}

// credentialFingerprint identifies the caller a cached response belongs to,
// without putting their credentials in a cache key.
func credentialFingerprint(r *http.Request) string {
	sum := sha256.New()
	for _, header := range []string{"Authorization", "Proxy-Authorization", "Cookie"} {
		sum.Write([]byte(r.Header.Get(header)))
		sum.Write([]byte{0})
	}
	return hex.EncodeToString(sum.Sum(nil))
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
