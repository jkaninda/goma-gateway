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
	"math"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/go-redis/redis_rate/v10"
	"github.com/jkaninda/njia"
	"github.com/redis/go-redis/v9"
)

const (
	maxTrackedClients = 100_000
	clientIdleTTL     = 10 * time.Minute
)

// RateLimiter defines requests limit properties.
type RateLimiter struct {
	requests    int
	burst       int
	unit        string
	id          string
	clientMap   map[string]*Client
	mu          sync.Mutex
	origins     []string
	redisBased  bool
	redis       *redis.Client
	pathBased   bool
	path        string
	paths       []string
	banList     map[string]time.Time
	banAfter    int
	banDuration time.Duration
	strikeMap   map[string]int
	ctx         context.Context
	keyStrategy RateLimitKeyStrategy
}

type RateLimitKeyStrategy struct {
	Source string // "ip", "header", "cookie"
	Name   string // header name or cookie name
}

// RateLimitMiddleware limits request based on the number of requests per time unit.
func (rl *RateLimiter) RateLimitMiddleware() njia.Middleware {
	var window time.Duration
	switch rl.unit {
	case "hour":
		window = time.Hour
	case "minute":
		window = time.Minute
	case "second":
		fallthrough
	default:
		window = time.Second
	}

	// Calculate refill rate (tokens per second)
	refillRate := float64(rl.requests) / window.Seconds()

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			contentType := getContentType(r)
			if len(rl.paths) > 0 && !isPathMatching(r.URL.Path, rl.path, rl.paths) {
				logger.Debug("RateLimit:: Request path not subject to rate limiting", "url", r.URL)
				next.ServeHTTP(w, r)
				return
			}

			// Get client identifier based on key strategy
			clientIdentifier := rl.getClientIdentifier(r)
			if clientIdentifier == "" {
				logger.Warn("RateLimit:: Unable to identify client", "url", r.URL)
				RespondWithError(w, r, http.StatusInternalServerError, "500 Bad Request: Unable to identify client", nil, contentType)
				return
			}
			logger.Debug("RateLimit:: Request path matched", "url", r.URL, "identifier", redactIdentifier(clientIdentifier))

			// Check if the client is banned
			if rl.banAfter > 0 && rl.banDuration > 0 {
				if ok, banUntil := rl.isBanned(clientIdentifier); ok {
					logger.Warn("Client is banned", "identifier", redactIdentifier(clientIdentifier), "until", banUntil)
					RespondWithError(w, r, http.StatusForbidden, "403 Forbidden: Client temporarily banned due to repeated abuse", nil, contentType)
					return
				}
			}

			// Redis-based rate limiting with burst
			if rl.redisBased && rl.redis != nil {
				if err := rl.redisRateLimiterWithBurst(clientIdentifier); err != nil {
					if errors.Is(err, errRateLimitUnavailable) {
						// Let the request through rather than 429 the whole
						// gateway on a Redis blip, and do not hold it against
						// the client.
						logger.Error("RateLimit:: backend unavailable, allowing the request", "error", err)
						next.ServeHTTP(w, r)
						return
					}
					rl.registerStrike(clientIdentifier)
					logger.Debug("RateLimit:: Too many requests", "identifier", redactIdentifier(clientIdentifier), "client_ip", rl.getIPAddress(r), "url", r.URL, "user_agent", r.UserAgent())
					logger.Warn("Too many requests", "client_ip", rl.getIPAddress(r), "url", r.URL, "user_agent", r.UserAgent())
					RespondWithError(w, r, http.StatusTooManyRequests, "429 Too many requests. Try again later.", nil, contentType)
					return
				}
			} else {
				// Memory-based rate limiting with token bucket algorithm
				rl.mu.Lock()
				rl.evictStaleLocked()
				client, exists := rl.clientMap[clientIdentifier]
				now := time.Now()

				if !exists {
					// New client: start with full burst capacity
					burstCapacity := rl.requests + rl.burst
					client = &Client{
						RequestCount: 0,
						ExpiresAt:    now.Add(window),
						Tokens:       float64(burstCapacity),
						LastRefill:   now,
					}
					rl.clientMap[clientIdentifier] = client
				} else {
					// Refill tokens based on time elapsed
					elapsed := now.Sub(client.LastRefill).Seconds()
					tokensToAdd := elapsed * refillRate

					// Cap tokens at burst capacity
					burstCapacity := float64(rl.requests + rl.burst)
					client.Tokens = math.Min(client.Tokens+tokensToAdd, burstCapacity)
					client.LastRefill = now
				}

				// Try to consume one token
				if client.Tokens >= 1.0 {
					client.Tokens -= 1.0
					client.RequestCount++
					rl.mu.Unlock()

					logger.Debug("RateLimit:: Request allowed", "identifier", redactIdentifier(clientIdentifier), "tokens_remaining", client.Tokens)
				} else {
					rl.mu.Unlock()
					rl.registerStrike(clientIdentifier)
					logger.Debug("RateLimit:: Too many requests", "identifier", redactIdentifier(clientIdentifier), "client_ip", rl.getIPAddress(r), "url", r.URL, "user_agent", r.UserAgent(), "tokens", client.Tokens)
					logger.Warn("Too many requests", "client_ip", rl.getIPAddress(r), "url", r.URL, "user_agent", r.UserAgent())

					if allowedOrigin(rl.origins, r.Header.Get("Origin")) {
						w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
						w.Header().Add("Vary", "Origin")
					}
					RespondWithError(w, r, http.StatusTooManyRequests, "429 Too many requests. Try again later.", nil, contentType)
					return
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

// evictStaleLocked drops buckets and bans that no longer decide anything. The
// caller must hold rl.mu.
func (rl *RateLimiter) evictStaleLocked() {
	now := time.Now()

	for identifier, banUntil := range rl.banList {
		if now.After(banUntil) {
			delete(rl.banList, identifier)
			delete(rl.strikeMap, identifier)
		}
	}

	if len(rl.clientMap) < maxTrackedClients {
		if len(rl.clientMap)%evictionInterval != 0 {
			return
		}
	}

	for identifier, client := range rl.clientMap {
		if now.Sub(client.LastRefill) > clientIdleTTL {
			delete(rl.clientMap, identifier)
			// Strikes outlive the bucket they belong to unless they are dropped
			// here; a standing ban keeps its own count.
			if _, banned := rl.banList[identifier]; !banned {
				delete(rl.strikeMap, identifier)
			}
		}
	}

	// Still over the cap after dropping idle buckets: the traffic is not idle,
	// it is adversarial. Evict the least recently active buckets down to the
	// watermark.
	//
	// This used to clear clientMap and strikeMap outright, which handed every
	// legitimate client a full bucket and wiped every strike — so minting
	// enough distinct keys was a repeatable, global rate-limit reset.
	if len(rl.clientMap) >= maxTrackedClients {
		logger.Warn("Rate limiter is tracking too many distinct clients, evicting the least recently active",
			"tracked", len(rl.clientMap), "limit", maxTrackedClients,
			"hint", "a keyStrategy on a client-supplied header or cookie lets one caller mint many keys")
		rl.evictLeastRecentLocked(len(rl.clientMap) - maxTrackedClients/2)
	}
}

// evictLeastRecentLocked drops the count least recently refilled buckets. The
// caller must hold rl.mu.
func (rl *RateLimiter) evictLeastRecentLocked(count int) {
	if count <= 0 {
		return
	}

	identifiers := make([]string, 0, len(rl.clientMap))
	for identifier := range rl.clientMap {
		identifiers = append(identifiers, identifier)
	}
	sort.Slice(identifiers, func(i, j int) bool {
		return rl.clientMap[identifiers[i]].LastRefill.Before(rl.clientMap[identifiers[j]].LastRefill)
	})

	if count > len(identifiers) {
		count = len(identifiers)
	}
	for _, identifier := range identifiers[:count] {
		delete(rl.clientMap, identifier)
		if _, banned := rl.banList[identifier]; !banned {
			delete(rl.strikeMap, identifier)
		}
	}
}

// evictionInterval spreads the sweep over many requests.
const evictionInterval = 256

func (rl *RateLimiter) getClientIdentifier(r *http.Request) string {
	ip := rl.getIPAddress(r)
	if rl.keyStrategy.Source == "" {
		if len(rl.paths) > 0 {
			logger.Debug("RateLimit:: Using route-based identifier", "route", rl.id)
			return fmt.Sprintf("route:%s:ip:%s", rl.id, ip)
		}
		return fmt.Sprintf("global:ip:%s", ip)
	}
	switch strings.ToLower(rl.keyStrategy.Source) {
	case "header":
		if rl.keyStrategy.Name == "" {
			logger.Warn("RateLimit:: Header name not specified, falling back to IP")
			return fmt.Sprintf("ip:%s", ip)
		}
		value := strings.TrimSpace(r.Header.Get(rl.keyStrategy.Name))
		if value == "" {
			return fmt.Sprintf("ip:%s", ip)
		}

		return fmt.Sprintf("ip:%s:header:%s:value:%s", ip, rl.keyStrategy.Name, value)

	case "cookie":
		if rl.keyStrategy.Name == "" {
			logger.Warn("RateLimit:: Cookie name not specified, falling back to IP")
			return fmt.Sprintf("ip:%s", ip)
		}
		cookie, err := r.Cookie(rl.keyStrategy.Name)
		if err != nil || cookie.Value == "" {
			return fmt.Sprintf("ip:%s", ip)
		}
		return fmt.Sprintf("ip:%s:cookie:%s:value:%s", ip, rl.keyStrategy.Name, strings.TrimSpace(cookie.Value))

	case "ip":
		fallthrough
	default:
		return fmt.Sprintf("ip:%s", ip)
	}
}

// getIPAddress extracts the client IP address from the request.
func (rl *RateLimiter) getIPAddress(r *http.Request) string {
	clientIP, _, err := net.SplitHostPort(RealIP(r))
	if err != nil {
		clientIP = RealIP(r)
	}
	return clientIP
}

func (rl *RateLimiter) isBanned(identifier string) (bool, time.Time) {
	if rl.redisBased && rl.redis != nil {
		key := fmt.Sprintf("rate:ban:%s", identifier)
		ttl, err := rl.redis.TTL(rl.ctx, key).Result()
		if err != nil || ttl <= 0 {
			return false, time.Time{}
		}
		return true, time.Now().Add(ttl)
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()
	banUntil, banned := rl.banList[identifier]
	if banned && time.Now().Before(banUntil) {
		return true, banUntil
	}
	return false, time.Time{}
}

func (rl *RateLimiter) registerStrike(identifier string) {
	if rl.banAfter == 0 {
		return
	}
	if rl.redisBased && rl.redis != nil {
		strikeKey := fmt.Sprintf("rate:strikes:%s", identifier)
		banKey := fmt.Sprintf("rate:ban:%s", identifier)

		// Increment strike count
		count, err := rl.redis.Incr(rl.ctx, strikeKey).Result()
		if err != nil {
			logger.Error("RateLimit:: Failed to increment strike", "identifier", redactIdentifier(identifier), "error", err)
			return
		}

		// Set TTL for strike
		_ = rl.redis.Expire(rl.ctx, strikeKey, rl.banDuration).Err()

		// Ban if threshold reached
		if int(count) >= rl.banAfter {
			_ = rl.redis.Set(rl.ctx, banKey, "banned", rl.banDuration).Err()
			_ = rl.redis.Del(rl.ctx, strikeKey).Err()
			logger.Debug("RateLimit:: Client banned (redis)", "identifier", redactIdentifier(identifier), "duration", rl.banDuration)
		}
	} else {
		rl.mu.Lock()
		defer rl.mu.Unlock()
		rl.strikeMap[identifier]++
		if rl.strikeMap[identifier] >= rl.banAfter {
			rl.banList[identifier] = time.Now().Add(rl.banDuration)
			delete(rl.strikeMap, identifier)
			logger.Debug("RateLimit:: Client banned (memory)", "identifier", redactIdentifier(identifier), "duration", rl.banDuration)
		}
	}
}

// redisRateLimiterWithBurst handles rate limiting with Redis using burst.
func (rl *RateLimiter) redisRateLimiterWithBurst(key string) error {
	var limit redis_rate.Limit
	burst := rl.burst
	switch rl.unit {
	case "hour":
		limit = redis_rate.PerHour(rl.requests)
		limit.Burst = rl.requests + burst
	case "minute":
		limit = redis_rate.PerMinute(rl.requests)
		limit.Burst = rl.requests + burst
	default:
		limit = redis_rate.PerSecond(rl.requests)
		limit.Burst = rl.requests + burst
	}

	// AllowN with n=1 (consume 1 token)
	res, err := limiter.AllowN(rl.ctx, key, limit, 1)
	if err != nil {
		// A Redis outage is not a rate-limit decision. Returning it as one
		// 429'd every request and registered a strike against every client
		// until all of them were banned, while isBanned failed open on the
		// same error — so the two halves disagreed about which way to fail.
		return fmt.Errorf("%w: %v", errRateLimitUnavailable, err)
	}
	if res.Allowed == 0 {
		return errRateLimitExceeded
	}
	return nil
}

var (
	// errRateLimitExceeded means the limiter decided: this client is over.
	errRateLimitExceeded = errors.New("requests limit exceeded")
	// errRateLimitUnavailable means the limiter could not decide at all.
	errRateLimitUnavailable = errors.New("rate limit backend unavailable")
)

// redactIdentifier makes a rate-limit key safe to log.
//
// Under keyStrategy {source: cookie} the key embeds the cookie value, which for
// a session cookie is the session itself — logging it at debug level put live
// credentials in the log file. The prefix stays readable so an operator can
// still tell buckets apart, and the value is replaced by a short digest.
func redactIdentifier(identifier string) string {
	index := strings.Index(identifier, ":value:")
	if index < 0 {
		return identifier
	}
	sum := sha256.Sum256([]byte(identifier[index+len(":value:"):]))
	return identifier[:index] + ":value:" + hex.EncodeToString(sum[:])[:12]
}
