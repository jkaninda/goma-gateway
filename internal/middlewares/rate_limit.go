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
	"errors"
	"fmt"
	"github.com/go-redis/redis_rate/v10"
	"github.com/gorilla/mux"
	"net"
	"net/http"
	"time"
)

// RateLimitMiddleware limits request based on the number of requests peer minutes.
func (rl *RateLimiter) RateLimitMiddleware() mux.MiddlewareFunc {
	var window time.Duration
	var clientID string
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
			clientIP, _, err := net.SplitHostPort(getRealIP(r))
			if err != nil {
				clientIP = getRealIP(r)
			}
			clientID = fmt.Sprintf("%s:%s", rl.id, clientIP)
			// Path-based rate limiting
			if rl.pathBased && len(rl.paths) > 0 {
				match, path := IsPathMatching(r.URL.Path, "", rl.paths)
				clientID = fmt.Sprintf("%s:%s:%s", path, rl.id, clientIP)
				logger.Debug("Path-based rate limiting", "path", path, "clientID", clientID)
				// If the request path does not match any of the specified paths, skip rate limiting
				if !match {
					next.ServeHTTP(w, r)
					return
				}
			}
			// Check if the IP is banned
			if rl.banAfter > 0 && rl.banDuration > 0 {
				if ok, banUntil := rl.isBanned(clientIP); ok {
					logger.Warn("IP is banned", "ip", clientIP, "until", banUntil)
					RespondWithError(w, r, http.StatusForbidden, "403 Forbidden: IP temporarily banned due to repeated abuse", nil, contentType)
					return
				}
			}

			// Redis-based rate limiting
			if rl.redisBased && rl.redis != nil {
				if err = rl.redisRateLimiter(clientID); err != nil {
					rl.registerStrike(clientIP)
					logger.Warn("RateLimit:: Too many requests", "ip", clientIP, "url", r.URL, "user_agent", r.UserAgent())
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
					rl.registerStrike(clientIP)
					logger.Warn("RateLimit:: Too many requests", "ip", clientIP, "url", r.URL, "user_agent", r.UserAgent())

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

func (rl *RateLimiter) isBanned(ip string) (bool, time.Time) {
	if rl.redisBased && rl.redis != nil {
		key := fmt.Sprintf("rate:ban:%s", ip)
		ttl, err := rl.redis.TTL(rl.ctx, key).Result()
		if err != nil || ttl <= 0 {
			return false, time.Time{}
		}
		return true, time.Now().Add(ttl)
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()
	banUntil, banned := rl.banList[ip]
	if banned && time.Now().Before(banUntil) {
		return true, banUntil
	}
	return false, time.Time{}
}

func (rl *RateLimiter) registerStrike(ip string) {
	if rl.banAfter == 0 {
		return
	}
	if rl.redisBased && rl.redis != nil {
		strikeKey := fmt.Sprintf("rate:strikes:%s", ip)
		banKey := fmt.Sprintf("rate:ban:%s", ip)

		// Increment strike count
		count, err := rl.redis.Incr(rl.ctx, strikeKey).Result()
		if err != nil {
			logger.Error("RateLimit:: Failed to increment strike", "ip", ip, "error", err)
			return
		}

		// Set TTL for strike
		_ = rl.redis.Expire(rl.ctx, strikeKey, rl.banDuration).Err()

		// Ban if threshold reached
		if int(count) >= rl.banAfter {
			_ = rl.redis.Set(rl.ctx, banKey, "banned", rl.banDuration).Err()
			_ = rl.redis.Del(rl.ctx, strikeKey).Err()
			logger.Debug("RateLimit:: IP banned (redis)", "ip", ip, "duration", rl.banDuration)
		}
	} else {
		rl.mu.Lock()
		defer rl.mu.Unlock()
		rl.strikeMap[ip]++
		if rl.strikeMap[ip] >= rl.banAfter {
			rl.banList[ip] = time.Now().Add(rl.banDuration)
			delete(rl.strikeMap, ip)
			logger.Debug("RateLimit:: IP banned (memory)", "ip", ip, "duration", rl.banDuration)
		}
	}
}

// redisRateLimiter, handle rateLimit
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
