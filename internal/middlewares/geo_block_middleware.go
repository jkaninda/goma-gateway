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
	"net"
	"net/http"
	"strings"
)

// GeoBlock is country-based access control. Deny=false makes Countries an
// allowlist (only those pass); Deny=true makes it a blocklist. Country codes are
// ISO 3166-1 alpha-2, resolved from the client IP by the injected Resolve func
// (the gateway's GeoIP lookup). Private/loopback clients bypass the check, and an
// unresolved country follows AllowUnknown (fail-open by default). CountryHeader,
// when set, carries the resolved country to the upstream. The raw IP is used only
// for the lookup and never leaves the gateway.
type GeoBlock struct {
	Name          string
	Deny          bool
	Countries     map[string]struct{}
	StatusCode    int
	Message       string
	AllowUnknown  bool
	CountryHeader string
	Resolve       func(ip string) string
	OnDeny        func(country string) // optional metrics hook
}

func (g GeoBlock) status() int {
	if g.StatusCode > 0 {
		return g.StatusCode
	}
	return http.StatusForbidden
}

func (g GeoBlock) message() string {
	if g.Message != "" {
		return g.Message
	}
	return "Access denied from your region"
}

// Middleware enforces the country policy.
func (g GeoBlock) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if g.Resolve == nil || len(g.Countries) == 0 {
			logger.Warn(">> GeoBlock: no GeoIP resolver or countries configured; passing through")
			next.ServeHTTP(w, r)
			return
		}

		ip := RealIP(r)
		// Internal traffic (loopback/private/link-local) is never geo-fenced.
		if isInternalIP(ip) {
			next.ServeHTTP(w, r)
			return
		}

		country := strings.ToUpper(g.Resolve(ip))
		if country == "" {
			if g.AllowUnknown {
				next.ServeHTTP(w, r)
				return
			}
			g.deny(w, r, "")
			return
		}

		_, listed := g.Countries[country]
		blocked := (g.Deny && listed) || (!g.Deny && !listed)
		if blocked {
			g.deny(w, r, country)
			return
		}

		if g.CountryHeader != "" {
			r.Header.Set(g.CountryHeader, country)
		}
		next.ServeHTTP(w, r)
	})
}

func (g GeoBlock) deny(w http.ResponseWriter, r *http.Request, country string) {
	if g.OnDeny != nil {
		g.OnDeny(country)
	}
	logger.Warn("Blocked request",
		"ip", RealIP(r),
		"path", r.URL.Path,
		"country", country,
		"reason", "country not allowed",
	)
	RespondWithError(w, r, g.status(), g.message(), nil, getContentType(r))
}

// isInternalIP reports whether ip is loopback, private, link-local or
// unspecified — traffic that shouldn't be geolocated or blocked.
func isInternalIP(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	return parsed.IsLoopback() || parsed.IsPrivate() || parsed.IsLinkLocalUnicast() || parsed.IsUnspecified()
}
