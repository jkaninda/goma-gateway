package middlewares

/*
Copyright 2024 Jonas Kaninda

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
import (
	"fmt"
	"github.com/gorilla/mux"
	"github.com/jkaninda/goma-gateway/pkg/logger"
	"net"
	"net/http"
	"time"
)

// RateLimitMiddleware limits request based on the number of tokens peer minutes.
func (rl *TokenRateLimiter) RateLimitMiddleware() mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			contentType := r.Header.Get("Content-Type")

			if !rl.Allow() {
				logger.Error("Too many requests from IP: %s %s %s", getRealIP(r), r.URL, r.UserAgent())
				// Rate limit exceeded, return a 429 Too Many Requests response
				RespondWithError(w, r, http.StatusForbidden, fmt.Sprintf("%d Too many requests, API requests limit exceeded. Please try again later", http.StatusForbidden), nil, contentType)
				return
			}
			// Proceed to the next handler if requests limit is not exceeded
			next.ServeHTTP(w, r)
		})
	}
}

// RateLimitMiddleware limits request based on the number of requests peer minutes.
func (rl *RateLimiter) RateLimitMiddleware() mux.MiddlewareFunc {
	window := time.Second //  requests per minute
	if len(rl.unit) != 0 && rl.unit == "hour" {
		window = time.Hour
	}
	if len(rl.unit) != 0 && rl.unit == "minute" {
		window = time.Minute
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get the client's IP address
			clientIP, _, err := net.SplitHostPort(getRealIP(r))
			if err != nil {
				clientIP = getRealIP(r)
			}
			contentType := r.Header.Get("Content-Type")
			clientID := fmt.Sprintf("%s-%s", rl.id, clientIP) // Generate client Id, ID+ route ID
			if rl.redisBased {
				err := redisRateLimiter(clientID, rl.unit, rl.requests)
				if err != nil {
					logger.Error("Redis Rate limiter error: %s", err.Error())
					logger.Error("Too many requests from IP: %s %s %s", clientIP, r.URL, r.UserAgent())
					return
				}
			} else {
				rl.mu.Lock()
				client, exists := rl.clientMap[clientID]
				if !exists || time.Now().After(client.ExpiresAt) {
					client = &Client{
						RequestCount: 0,
						ExpiresAt:    time.Now().Add(window),
					}
					rl.clientMap[clientID] = client
				}
				client.RequestCount++
				rl.mu.Unlock()

				if client.RequestCount > rl.requests {
					logger.Error("Too many requests from IP: %s %s %s", clientIP, r.URL, r.UserAgent())
					// Update Origin Cors Headers
					if allowedOrigin(rl.origins, r.Header.Get("Origin")) {
						w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
					}
					RespondWithError(w, r, http.StatusTooManyRequests, fmt.Sprintf("%d Too many requests, API requests limit exceeded. Please try again later", http.StatusTooManyRequests), nil, contentType)
					return
				}
			}

			// Proceed to the next handler if the request limit is not exceeded
			next.ServeHTTP(w, r)
		})
	}
}
