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
	"bytes"
	"fmt"
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
		clientIP, _, err := net.SplitHostPort(RealIP(r))
		if err != nil {
			clientIP = RealIP(r)
		}
		contentType := getContentType(r)

		// Check IP against source ranges
		isAllowed := access.Action != "DENY"
		for _, entry := range access.SourceRanges {
			if isIPAllowed(clientIP, entry) {
				if isAllowed {
					next.ServeHTTP(w, r)
				} else {
					logger.Warn(" IP address in the blocklist, access not allowed", "ip", clientIP)
					RespondWithError(w, r, http.StatusForbidden, fmt.Sprintf("%d %s", http.StatusForbidden, http.StatusText(http.StatusForbidden)), access.Origins, contentType)
				}
				return
			}
		}

		// Final response for disallowed IPs
		if isAllowed {
			logger.Warn("IP address not allowed", "ip", clientIP)
			RespondWithError(w, r, http.StatusForbidden, fmt.Sprintf("%d %s", http.StatusForbidden, http.StatusText(http.StatusForbidden)), access.Origins, contentType)
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

// ipInRange reports whether ipStr falls between startIP and endIP inclusive.
//
// This used to compare octet by octet and reject the address as soon as any one
// octet fell outside its counterpart's. For a range crossing an octet boundary
// — 10.0.0.50-10.0.3.20 — the client 10.0.1.30 failed on the last octet and was
// let through a DENY rule. Comparing the addresses as whole numbers is the only
// correct reading of a range, and using the 16-byte form makes IPv6 ranges work
// too, where To4 previously returned nil and nothing ever matched.
func ipInRange(ipStr, startIP, endIP string) bool {
	ip := net.ParseIP(ipStr)
	start := net.ParseIP(startIP)
	end := net.ParseIP(endIP)

	if ip == nil || start == nil || end == nil {
		return false
	}

	// An IPv4 address and an IPv6 range are not comparable even once both are
	// 16 bytes wide, so require the families to agree.
	if (ip.To4() == nil) != (start.To4() == nil) || (start.To4() == nil) != (end.To4() == nil) {
		return false
	}

	ipBytes, startBytes, endBytes := ip.To16(), start.To16(), end.To16()
	if ipBytes == nil || startBytes == nil || endBytes == nil {
		return false
	}

	return bytes.Compare(ipBytes, startBytes) >= 0 && bytes.Compare(ipBytes, endBytes) <= 0
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
