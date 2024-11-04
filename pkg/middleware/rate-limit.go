package middleware

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
	"encoding/json"
	"github.com/gorilla/mux"
	"github.com/jkaninda/goma-gateway/internal/logger"
	"net/http"
	"time"
)

// RateLimitMiddleware limits request based on the number of tokens peer minutes.
func (rl *TokenRateLimiter) RateLimitMiddleware() mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !rl.Allow() {
				// Rate limit exceeded, return a 429 Too Many Requests response
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusTooManyRequests)
				err := json.NewEncoder(w).Encode(ProxyResponseError{
					Success: false,
					Code:    http.StatusTooManyRequests,
					Message: "Too many requests, API rate limit exceeded. Please try again later.",
				})
				if err != nil {
					return
				}
				return
			}

			// Proceed to the next handler if rate limit is not exceeded
			next.ServeHTTP(w, r)
		})
	}
}

// RateLimitMiddleware limits request based on the number of requests peer minutes.
func (rl *RateLimiter) RateLimitMiddleware() mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			clientID := getRealIP(r)
			rl.mu.Lock()
			client, exists := rl.ClientMap[clientID]
			if !exists || time.Now().After(client.ExpiresAt) {
				client = &Client{
					RequestCount: 0,
					ExpiresAt:    time.Now().Add(rl.Window),
				}
				rl.ClientMap[clientID] = client
			}
			client.RequestCount++
			rl.mu.Unlock()

			if client.RequestCount > rl.Requests {
				logger.Error("Too many requests from IP: %s %s %s", clientID, r.URL, r.UserAgent())
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusTooManyRequests)
				err := json.NewEncoder(w).Encode(ProxyResponseError{
					Success: false,
					Code:    http.StatusTooManyRequests,
					Message: "Too many requests, API rate limit exceeded. Please try again later.",
				})
				if err != nil {
					return
				}
				return
			}
			// Proceed to the next handler if rate limit is not exceeded
			next.ServeHTTP(w, r)
		})
	}
}
func getRealIP(r *http.Request) string {
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return ip
	}
	if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
		return ip
	}
	return r.RemoteAddr
}
