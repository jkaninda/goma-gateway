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
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRateLimitIdentifierIsScopedToLimiter(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-API-Key", "k1")
	for _, strategy := range []RateLimitKeyStrategy{{}, {Source: "ip"}, {Source: "header", Name: "X-API-Key"}} {
		a := RateLimit{Id: "orders:limit", Unit: "minute", Requests: 10, KeyStrategy: strategy}.NewRateLimiterWindow()
		b := RateLimit{Id: "payments:limit", Unit: "minute", Requests: 10, KeyStrategy: strategy}.NewRateLimiterWindow()
		if a.getClientIdentifier(req) == b.getClientIdentifier(req) {
			t.Errorf("strategy %+v: two limiters share the identifier %q, so they would share Redis counters and bans",
				strategy, a.getClientIdentifier(req))
		}
	}
}
