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
	"golang.org/x/oauth2"
	"io"
	"net"
	"net/http"
)

// printRoute prints routes
func printRoute(routes []Route) {
	t := table.NewWriter()
	t.AppendHeader(table.Row{"Name", "Path", "Rewrite", "Destination"})
	for _, route := range routes {
		if len(route.Backends) != 0 {
			t.AppendRow(table.Row{route.Name, route.Path, route.Rewrite, fmt.Sprintf("backends: [%d]", len(route.Backends))})

		} else {
			t.AppendRow(table.Row{route.Name, route.Path, route.Rewrite, route.Destination})
		}
	}
	fmt.Println(t.Render())
}

// getRealIP gets user real IP
func getRealIP(r *http.Request) string {
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return ip
	}
	if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
		return ip
	}
	return r.RemoteAddr
}

// getUserInfo returns struct of UserInfo
func (oauth *OauthRulerMiddleware) getUserInfo(token *oauth2.Token) (UserInfo, error) {
	oauthConfig := oauth2Config(oauth)
	// Call the user info endpoint with the token
	client := oauthConfig.Client(context.Background(), token)
	resp, err := client.Get(oauth.Endpoint.UserInfoURL)
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
