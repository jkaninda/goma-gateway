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
	"github.com/go-redis/redis_rate/v10"
	"github.com/gorilla/mux"
	"github.com/redis/go-redis/v9"
	"math"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
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
func (rl *RateLimiter) RateLimitMiddleware() mux.MiddlewareFunc {
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
			logger.Debug("RateLimit:: Request path matched", "url", r.URL, "identifier", clientIdentifier)

			// Check if the client is banned
			if rl.banAfter > 0 && rl.banDuration > 0 {
				if ok, banUntil := rl.isBanned(clientIdentifier); ok {
					logger.Warn("Client is banned", "identifier", clientIdentifier, "until", banUntil)
					RespondWithError(w, r, http.StatusForbidden, "403 Forbidden: Client temporarily banned due to repeated abuse", nil, contentType)
					return
				}
			}

			// Redis-based rate limiting with burst
			if rl.redisBased && rl.redis != nil {
				if err := rl.redisRateLimiterWithBurst(clientIdentifier); err != nil {
					rl.registerStrike(clientIdentifier)
					logger.Debug("RateLimit:: Too many requests", "identifier", clientIdentifier, "client_ip", rl.getIPAddress(r), "url", r.URL, "user_agent", r.UserAgent())
					logger.Warn("Too many requests", "client_ip", rl.getIPAddress(r), "url", r.URL, "user_agent", r.UserAgent())
					RespondWithError(w, r, http.StatusTooManyRequests, "429 Too many requests. Try again later.", nil, contentType)
					return
				}
			} else {
				// Memory-based rate limiting with token bucket algorithm
				rl.mu.Lock()
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

					logger.Debug("RateLimit:: Request allowed", "identifier", clientIdentifier, "tokens_remaining", client.Tokens)
				} else {
					rl.mu.Unlock()
					rl.registerStrike(clientIdentifier)
					logger.Debug("RateLimit:: Too many requests", "identifier", clientIdentifier, "client_ip", rl.getIPAddress(r), "url", r.URL, "user_agent", r.UserAgent(), "tokens", client.Tokens)
					logger.Warn("Too many requests", "client_ip", rl.getIPAddress(r), "url", r.URL, "user_agent", r.UserAgent())

					if allowedOrigin(rl.origins, r.Header.Get("Origin")) {
						w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
					}
					RespondWithError(w, r, http.StatusTooManyRequests, "429 Too many requests. Try again later.", nil, contentType)
					return
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

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
		return fmt.Sprintf("header:%s:value:%s", rl.keyStrategy.Name, value)

	case "cookie":
		if rl.keyStrategy.Name == "" {
			logger.Warn("RateLimit:: Cookie name not specified, falling back to IP")
			return fmt.Sprintf("ip:%s", ip)
		}
		cookie, err := r.Cookie(rl.keyStrategy.Name)
		if err != nil || cookie.Value == "" {
			return fmt.Sprintf("ip:%s", ip)
		}
		return fmt.Sprintf("cookie:%s:value:%s", rl.keyStrategy.Name, strings.TrimSpace(cookie.Value))

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
			logger.Error("RateLimit:: Failed to increment strike", "identifier", identifier, "error", err)
			return
		}

		// Set TTL for strike
		_ = rl.redis.Expire(rl.ctx, strikeKey, rl.banDuration).Err()

		// Ban if threshold reached
		if int(count) >= rl.banAfter {
			_ = rl.redis.Set(rl.ctx, banKey, "banned", rl.banDuration).Err()
			_ = rl.redis.Del(rl.ctx, strikeKey).Err()
			logger.Debug("RateLimit:: Client banned (redis)", "identifier", identifier, "duration", rl.banDuration)
		}
	} else {
		rl.mu.Lock()
		defer rl.mu.Unlock()
		rl.strikeMap[identifier]++
		if rl.strikeMap[identifier] >= rl.banAfter {
			rl.banList[identifier] = time.Now().Add(rl.banDuration)
			delete(rl.strikeMap, identifier)
			logger.Debug("RateLimit:: Client banned (memory)", "identifier", identifier, "duration", rl.banDuration)
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
		return err
	}
	if res.Allowed == 0 {
		return errors.New("requests limit exceeded")
	}
	return nil
}
