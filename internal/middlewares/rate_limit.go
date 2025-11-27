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
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// RateLimiter defines requests limit properties.
type RateLimiter struct {
	requests    int
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

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			contentType := getContentType(r)

			// Get client identifier based on key strategy
			clientIdentifier := rl.getClientIdentifier(r)
			if clientIdentifier == "" {
				logger.Warn("RateLimit:: Unable to identify client", "url", r.URL)
				RespondWithError(w, r, http.StatusBadRequest, "400 Bad Request: Unable to identify client", nil, contentType)
				return
			}

			clientID := fmt.Sprintf("%s:%s", rl.id, clientIdentifier)

			// Path-based rate limiting
			if rl.pathBased && len(rl.paths) > 0 {
				logger.Debug("RateLimit:: pathBased Processing request", "clientID", clientID, "url", r.URL, "path", rl.path, "paths", rl.paths, "request_path", r.URL.Path)
				match, path := IsPathMatching(r.URL.Path, rl.path, rl.paths)
				clientID = fmt.Sprintf("%s:%s:%s", path, rl.id, clientIdentifier)
				logger.Debug("Path-based rate limiting", "path", path, "clientID", clientID)
				// If the request path does not match any of the specified paths, skip rate limiting
				if !match {
					next.ServeHTTP(w, r)
					return
				}
			}

			// Check if the client is banned
			if rl.banAfter > 0 && rl.banDuration > 0 {
				if ok, banUntil := rl.isBanned(clientIdentifier); ok {
					logger.Warn("Client is banned", "identifier", clientIdentifier, "until", banUntil)
					RespondWithError(w, r, http.StatusForbidden, "403 Forbidden: Client temporarily banned due to repeated abuse", nil, contentType)
					return
				}
			}

			// Redis-based rate limiting
			if rl.redisBased && rl.redis != nil {
				if err := rl.redisRateLimiter(clientID); err != nil {
					rl.registerStrike(clientIdentifier)
					logger.Warn("RateLimit:: Too many requests", "identifier", clientIdentifier, "url", r.URL, "user_agent", r.UserAgent())
					RespondWithError(w, r, http.StatusTooManyRequests, "429 Too many requests. Try again later.", nil, contentType)
					return
				}
			} else {
				rl.mu.Lock()
				client, exists := rl.clientMap[clientID]
				now := time.Now()

				if !exists || now.After(client.ExpiresAt) {
					client = &Client{
						RequestCount: 1,
						ExpiresAt:    now.Add(window),
					}
					rl.clientMap[clientID] = client
				} else {
					client.RequestCount++
				}
				count := client.RequestCount
				rl.mu.Unlock()

				if count > rl.requests {
					rl.registerStrike(clientIdentifier)
					logger.Warn("RateLimit:: Too many requests", "identifier", clientIdentifier, "url", r.URL, "user_agent", r.UserAgent())

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

// getClientIdentifier extracts the client identifier based on the configured key strategy.
func (rl *RateLimiter) getClientIdentifier(r *http.Request) string {
	if rl.keyStrategy.Source == "" {
		return rl.getIPAddress(r)
	}

	switch strings.ToLower(rl.keyStrategy.Source) {
	case "header":
		if rl.keyStrategy.Name == "" {
			logger.Warn("RateLimit:: Header name not specified, falling back to IP")

			return rl.getIPAddress(r)
		}
		logger.Debug("RateLimit:: Using header for rate limiting", "header", rl.keyStrategy.Name)
		headerValue := r.Header.Get(rl.keyStrategy.Name)
		if headerValue == "" {
			logger.Debug("RateLimit:: Header not found, falling back to IP", "header", rl.keyStrategy.Name)
			return rl.getIPAddress(r)
		}
		headerValue = strings.TrimSpace(headerValue)
		return fmt.Sprintf("header:%s:%s", rl.keyStrategy.Name, headerValue)

	case "cookie":
		if rl.keyStrategy.Name == "" {
			logger.Warn("RateLimit:: Cookie name not specified, falling back to IP")
			return rl.getIPAddress(r)
		}
		logger.Debug("RateLimit:: Using cookie for rate limiting", "cookie", rl.keyStrategy.Name)
		cookie, err := r.Cookie(rl.keyStrategy.Name)
		if err != nil || cookie.Value == "" {
			logger.Debug("RateLimit:: Cookie not found, falling back to IP", "cookie", rl.keyStrategy.Name)
			return rl.getIPAddress(r)
		}
		cookieValue := strings.TrimSpace(cookie.Value)
		return fmt.Sprintf("cookie:%s:%s", rl.keyStrategy.Name, cookieValue)

	case "ip":
		fallthrough
	default:
		return rl.getIPAddress(r)
	}
}

// getIPAddress extracts the client IP address from the request.
func (rl *RateLimiter) getIPAddress(r *http.Request) string {
	clientIP, _, err := net.SplitHostPort(RealIP(r))
	if err != nil {
		clientIP = RealIP(r)
	}
	return fmt.Sprintf("ip:%s", clientIP)
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

// redisRateLimiter handles rate limiting with Redis.
func (rl *RateLimiter) redisRateLimiter(key string) error {
	var limit redis_rate.Limit
	switch rl.unit {
	case "hour":
		limit = redis_rate.PerHour(rl.requests)
	case "minute":
		limit = redis_rate.PerMinute(rl.requests)
	default:
		limit = redis_rate.PerSecond(rl.requests)
	}

	res, err := limiter.Allow(rl.ctx, key, limit)
	if err != nil {
		return err
	}
	if res.Remaining == 0 {
		return errors.New("requests limit exceeded")
	}
	return nil
}
