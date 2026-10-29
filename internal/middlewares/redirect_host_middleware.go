/*
 * Copyright 2026 Jonas Kaninda
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

const (
	WWWAdd    = "add"
	WWWRemove = "remove"
)

// RedirectHost redirects to another host, keeping the scheme, path and query.
// Exactly one of WWW and Host is set: WWW derives the target from the request
// host, Host names a fixed canonical one.
type RedirectHost struct {
	WWW       string // "add" or "remove"
	Host      string
	Permanent bool
	// Hosts are the route's configured hosts. A request for any other host is
	// passed through, so a client-supplied Host header cannot steer the Location.
	Hosts []string
}

// Middleware redirects requests whose host differs from the target host.
func (rh *RedirectHost) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/.well-known/acme-challenge/") {
			next.ServeHTTP(w, r)
			return
		}
		target, ok := rh.target(r.Host)
		if !ok {
			next.ServeHTTP(w, r)
			return
		}
		u := scheme(r) + "://" + target + r.URL.EscapedPath()
		if r.URL.RawQuery != "" {
			u += "?" + r.URL.RawQuery
		}
		status := http.StatusFound
		if rh.Permanent {
			status = http.StatusMovedPermanently
		}
		http.Redirect(w, r, u, status)
	})
}

// target returns the host to redirect to, and false when the request should pass through.
func (rh *RedirectHost) target(requestHost string) (string, bool) {
	hostname, port := requestHost, ""
	if h, p, err := net.SplitHostPort(requestHost); err == nil {
		hostname, port = h, p
	}
	hostname = strings.TrimSuffix(strings.ToLower(hostname), ".")
	if hostname == "" || net.ParseIP(hostname) != nil || !rh.servesHost(hostname) {
		return "", false
	}

	var to string
	switch {
	case rh.Host != "":
		// A fixed host is used as written, port included; the request's port is not carried over.
		to = strings.ToLower(rh.Host)
		name := to
		if h, _, err := net.SplitHostPort(to); err == nil {
			name = h
		}
		return to, name != hostname
	case rh.WWW == WWWAdd:
		if strings.HasPrefix(hostname, "www.") {
			return "", false
		}
		to = "www." + hostname
	case rh.WWW == WWWRemove:
		if !strings.HasPrefix(hostname, "www.") {
			return "", false
		}
		to = strings.TrimPrefix(hostname, "www.")
	default:
		return "", false
	}
	if port != "" {
		to = net.JoinHostPort(to, port)
	}
	return to, true
}

func (rh *RedirectHost) servesHost(hostname string) bool {
	if len(rh.Hosts) == 0 {
		return true
	}
	for _, h := range rh.Hosts {
		if strings.EqualFold(strings.TrimSuffix(h, "."), hostname) {
			return true
		}
	}
	return false
}
