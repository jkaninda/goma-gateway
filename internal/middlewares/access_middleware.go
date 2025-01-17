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
	"github.com/jkaninda/goma-gateway/pkg/logger"
	"github.com/jkaninda/goma-gateway/util"
	"net/http"
	"strings"
	"time"
)

// AccessMiddleware checks if the request path is forbidden and returns 403 Forbidden
func (blockList AccessListMiddleware) AccessMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		contentType := r.Header.Get("Content-Type")
		if isPathMatching(r.URL.Path, blockList.Path, blockList.Paths) {
			logger.Error("%s: %s access forbidden", getRealIP(r), r.URL.Path)
			RespondWithError(w, r, http.StatusForbidden, fmt.Sprintf("%d %s", http.StatusForbidden, http.StatusText(http.StatusForbidden)), blockList.Origins, contentType)
			return

		}
		next.ServeHTTP(w, r)
	})
}

// Helper function to determine if the request path is blocked
func isMatchingPath(requestPath, blockedPath string) bool {
	// Handle exact match
	if requestPath == blockedPath {
		return true
	}
	// Handle wildcard match (e.g., /admin/* should block /admin and any subpath)
	if strings.HasSuffix(blockedPath, "/*") {
		basePath := strings.TrimSuffix(blockedPath, "/*")
		if strings.HasPrefix(requestPath, basePath) {
			return true
		}
	}
	return false
}
func isProtectedPath(urlPath, prefix string, paths []string) bool {
	for _, path := range paths {
		return isMatchingPath(urlPath, util.ParseURLPath(prefix+path))
	}
	return false
}

// NewRateLimiter creates a new requests limiter with the specified refill requests and token capacity
func NewRateLimiter(maxTokens int, refillRate time.Duration) *TokenRateLimiter {
	return &TokenRateLimiter{
		tokens:     maxTokens,
		maxTokens:  maxTokens,
		refillRate: refillRate,
		lastRefill: time.Now(),
	}
}

// Allow checks if a request is allowed based on the current token bucket
func (rl *TokenRateLimiter) Allow() bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	// Refill tokens based on the time elapsed
	now := time.Now()
	elapsed := now.Sub(rl.lastRefill)
	tokensToAdd := int(elapsed / rl.refillRate)
	if tokensToAdd > 0 {
		rl.tokens = min(rl.maxTokens, rl.tokens+tokensToAdd)
		rl.lastRefill = now
	}

	// Check if there are enough tokens to allow the request
	if rl.tokens > 0 {
		rl.tokens--
		return true
	}

	// Reject request if no tokens are available
	return false
}
