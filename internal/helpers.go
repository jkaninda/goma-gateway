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
	"context"
	"encoding/json"
	"fmt"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jkaninda/goma-gateway/util"
	"golang.org/x/oauth2"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// printRoute prints routes
func printRoute(routes []Route) {
	t := table.NewWriter()
	t.AppendHeader(table.Row{"Name", "Disabled", "Path", "Rewrite", "Destination"})
	for _, route := range routes {
		if len(route.Backends) != 0 {
			t.AppendRow(table.Row{route.Name, route.Disabled, route.Path, route.Rewrite, fmt.Sprintf("backends: [%d]", len(route.Backends))})

		} else {
			t.AppendRow(table.Row{route.Name, route.Disabled, route.Path, route.Rewrite, util.TruncateText(route.Destination, 25)})
		}
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

// getUserInfo returns struct of UserInfo
func (oauthRuler *OauthRulerMiddleware) getUserInfo(token *oauth2.Token) (UserInfo, error) {
	oauthConfig := oauth2Config(oauthRuler)
	// Call the user info endpoint with the token
	client := oauthConfig.Client(context.Background(), token)
	resp, err := client.Get(oauthRuler.Endpoint.UserInfoURL)
	if err != nil {
		return UserInfo{}, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			return
		}
	}(resp.Body)

	// Parse the user info
	var userInfo UserInfo
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return UserInfo{}, err
	}

	return userInfo, nil
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
	return r.Header.Get("Upgrade") == "websocket" && r.Header.Get("Connection") == "Upgrade"
}

// formatDuration formats the duration to either "X.Xms" or "X.Xs"
func formatDuration(d time.Duration) string {
	if d < time.Second {
		// Format as milliseconds with one decimal place
		return fmt.Sprintf("%.1fms", float64(d.Milliseconds()))
	}
	// Format as seconds with one decimal place
	return fmt.Sprintf("%.1fs", d.Seconds())
}
