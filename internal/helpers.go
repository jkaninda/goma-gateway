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

package internal

import (
	"fmt"
	"github.com/jedib0t/go-pretty/v6/table"
	goutils "github.com/jkaninda/go-utils"
	"github.com/jkaninda/goma-gateway/internal/certmanager"
	"net"
	"net/http"
	"strconv"
	"strings"
)

// printRoute prints routes
func printRoute(routes []Route) {
	t := table.NewWriter()
	t.AppendHeader(table.Row{"Name", "Enabled", "Priority", "Path", "Rewrite"})
	for _, route := range routes {

		t.AppendRow(table.Row{goutils.TruncateText(route.Name, 20), route.Enabled, route.Priority, goutils.TruncateText(route.Path, 20), route.Rewrite})

	}
	fmt.Println(t.Render())
}

// getRealIP extracts the real IP address of the client from the HTTP request.
func getRealIP(r *http.Request) string {
	// Check the X-Forwarded-For header for the client IP.
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Take the first IP in the comma-separated list.
		if ips := strings.Split(xff, ","); len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	// Check the X-Real-IP header as a fallback.
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return strings.TrimSpace(ip)
	}

	// Use the remote address if headers are not set.
	if ip, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return ip
	}

	// Return the raw remote address as a last resort.
	return r.RemoteAddr
}

func getContentType(r *http.Request) string {
	contentType := r.Header.Get("Accept")
	if contentType == "" {
		contentType = r.Header.Get("Content-Type")
	}
	return contentType
}

// validateIPAddress checks if the input is a valid IP address (IPv4 or IPv6)
func validateIPAddress(ip string) bool {
	return net.ParseIP(ip) != nil
}

// validateCIDR checks if the input is a valid CIDR notation
func validateCIDR(cidr string) bool {
	_, _, err := net.ParseCIDR(cidr)
	return err == nil
}

// isIPOrCIDR determines whether the input is an IP address or a CIDR
func isIPOrCIDR(input string) (isIP bool, isCIDR bool) {
	// Check if it's a valid IP address
	if net.ParseIP(input) != nil {
		return true, false
	}

	// Check if it's a valid CIDR
	if _, _, err := net.ParseCIDR(input); err == nil {
		return false, true
	}

	// Neither IP nor CIDR
	return false, false
}

// Helper function to determine the scheme (http or https)
func scheme(r *http.Request) string {
	// Check if the request is behind a reverse proxy
	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		return strings.ToLower(proto)
	}
	// Check if the request is using TLS
	if r.TLS != nil {
		return "https"
	}
	// Default to HTTP
	return "http"
}

// isWebSocketRequest checks if the request is a WebSocket request
func isWebSocketRequest(r *http.Request) bool {
	return r.Header.Get("Upgrade") == "websocket" && r.Method == http.MethodGet

}

func isSSE(r *http.Request) bool {
	return r.Header.Get("Accept") == "text/event-stream" && r.Method == http.MethodGet

}

func hasPositivePriority(r []Route) bool {
	for _, route := range r {
		if route.Priority > 0 {
			return true
		}
	}
	return false
}

// validateEntrypoint checks if the entrypoint address is valid.
// A valid entrypoint address should be in the format ":<port>" or "<IP>:<port>",
// where <IP> is a valid IP address and <port> is a valid port number (1-65535).
func validateEntrypoint(entrypoint string) bool {
	// Split the entrypoint into IP and port parts
	host, portStr, err := net.SplitHostPort(entrypoint)
	if err != nil {
		logger.Error("Error validating entrypoint address", "error", err)
		return false
	}

	// If the host is empty, it means the entrypoint is in the format ":<port>"
	// Otherwise, validate the IP address
	if host != "" {
		ip := net.ParseIP(host)
		if ip == nil {
			logger.Error("Error validating entrypoint address: invalid IP address", "addr", host)
			return false
		}
	}

	// Convert the port string to an integer
	port, err := strconv.Atoi(portStr)
	if err != nil {
		logger.Error("Error validating entrypoint address: invalid port", "error", err)
		return false
	}

	// Check if the port is within the valid range
	if port < 1 || port > 65535 {
		logger.Error("Error validating entrypoint address, invalid port", "port", port)
		return false
	}

	return true
}
func isPortValid(port int) bool {
	if port < 1 || port > 65535 {
		logger.Error("Invalid port number", "port", port)
		return false
	}
	return true
}

func allowedOrigin(origins []string, origin string) bool {
	for _, o := range origins {
		if o == "*" || o == origin {
			return true
		}
	}
	return false

}

func hostNames(routes []Route) []certmanager.Domain {
	hosts := extractHostsFromRoutes(routes)
	if len(hosts) == 0 {
		_ = []certmanager.Domain{}
		return nil
	}
	return hosts
}

// extractHostsFromRoutes collects all hosts from routes that have hosts defined
func extractHostsFromRoutes(routes []Route) []certmanager.Domain {
	var hosts []certmanager.Domain
	for _, route := range routes {
		if len(route.Hosts) > 0 && route.Enabled {
			hosts = append(hosts, certmanager.Domain{Name: route.Name, Hosts: route.Hosts})
		}
	}
	return hosts
}
