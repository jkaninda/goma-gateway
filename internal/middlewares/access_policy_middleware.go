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
	"github.com/jkaninda/goma-gateway/pkg/logger"
	"net"
	"net/http"
	"strings"
)

type AccessPolicy struct {
	Action       string
	SourceRanges []string
	Origins      []string
}

func (access AccessPolicy) AccessPolicyMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get the client's IP address
		clientIP, _, err := net.SplitHostPort(getRealIP(r))
		if err != nil {
			clientIP = getRealIP(r)
		}
		// Check IP against source ranges
		isAllowed := access.Action != "DENY"
		for _, entry := range access.SourceRanges {
			if isIPAllowed(clientIP, entry) {
				if isAllowed {
					next.ServeHTTP(w, r)
				} else {
					logger.Error("%s: IP address in the blocklist, access not allowed", clientIP)
					RespondWithError(w, r, http.StatusForbidden, http.StatusText(http.StatusForbidden), access.Origins, "")
				}
				return
			}
		}

		// Final response for disallowed IPs
		if isAllowed {
			logger.Error("%s: IP address not allowed", clientIP)
			RespondWithError(w, r, http.StatusForbidden, http.StatusText(http.StatusForbidden), access.Origins, "")
		} else {
			next.ServeHTTP(w, r)
		}
	})
}

// isIPAllowed checks if a client IP matches an entry (range, single IP or CIDR block).
func isIPAllowed(clientIP, entry string) bool {
	// Handle IP range
	if strings.Contains(entry, "-") {
		// Handle IP range
		startIP, endIP, err := parseIPRange(entry)
		return err == nil && ipInRange(clientIP, startIP, endIP)
	}
	// Handle CIDR
	if strings.Contains(entry, "/") {
		return ipInCIDR(clientIP, entry)
	}
	// Handle single IP
	return clientIP == entry
}

// / Parse a range string into start and end IPs
func parseIPRange(rangeStr string) (string, string, error) {
	parts := strings.Split(rangeStr, "-")
	if len(parts) != 2 {
		return "", "", http.ErrAbortHandler
	}

	startIP := strings.TrimSpace(parts[0])
	endIP := strings.TrimSpace(parts[1])

	if net.ParseIP(startIP) == nil || net.ParseIP(endIP) == nil {
		return "", "", http.ErrAbortHandler
	}

	return startIP, endIP, nil
}

// Check if an IP is in range
func ipInRange(ipStr, startIP, endIP string) bool {
	ip := net.ParseIP(ipStr)
	start := net.ParseIP(startIP)
	end := net.ParseIP(endIP)

	if ip == nil || start == nil || end == nil {
		return false
	}

	ipBytes := ip.To4()
	startBytes := start.To4()
	endBytes := end.To4()

	if ipBytes == nil || startBytes == nil || endBytes == nil {
		return false
	}

	for i := 0; i < 4; i++ {
		if ipBytes[i] < startBytes[i] || ipBytes[i] > endBytes[i] {
			return false
		}
	}
	return true
}

// Check if an IP is within a CIDR block
func ipInCIDR(ipStr, cidr string) bool {
	ip := net.ParseIP(ipStr)
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	return ipNet.Contains(ip)
}
