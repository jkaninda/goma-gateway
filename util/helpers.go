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

package util

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/robfig/cron/v3"
)

// FileExists checks if the file does exist
func FileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

// FolderExists checks if the folder does exist
func FolderExists(name string) bool {
	info, err := os.Stat(name)
	if os.IsNotExist(err) {
		return false
	}
	return info.IsDir()

}
func GetStringEnv(key, defaultValue string) string {
	val := os.Getenv(key)
	if val == "" {
		return defaultValue
	}
	return val
}

func GetIntEnv(key string, defaultValue int) int {
	val := os.Getenv(key)
	if val == "" {
		return defaultValue

	}
	i, err := strconv.Atoi(val)
	if err != nil {
		return defaultValue

	}
	return i

}
func GetBoolEnv(key string, defaultValue bool) bool {
	val := os.Getenv(key)
	if val == "" {
		return defaultValue

	}
	b, err := strconv.ParseBool(val)
	if err != nil {
		return defaultValue
	}
	return b

}

// SetEnv Set env
func SetEnv(name, value string) {
	if len(value) != 0 {
		err := os.Setenv(name, value)
		if err != nil {
			return
		}
	}

}
func MergeSlices(slice1, slice2 []string) []string {
	return append(slice1, slice2...)
}

// ParseURLPath removes duplicated [//]
//
// Ensures the path starts with a single leading slash
func ParseURLPath(urlPath string) string {
	// Replace any double slashes with a single slash
	urlPath = strings.ReplaceAll(urlPath, "//", "/")

	// Ensure the path starts with a single leading slash
	if !strings.HasPrefix(urlPath, "/") {
		urlPath = "/" + urlPath
	}
	return urlPath
}

func ParseRoutePath(path, blockedPath string) string {
	basePath := ParseURLPath(path)
	switch {
	case blockedPath == "":
		return basePath
	case strings.HasSuffix(blockedPath, "/*"):
		return basePath + blockedPath[:len(blockedPath)-2]
	case strings.HasSuffix(blockedPath, "*"):
		return basePath + blockedPath[:len(blockedPath)-1]
	default:
		return basePath + blockedPath
	}
}

func UrlParsePath(uri string) string {
	parse, err := url.Parse(uri)
	if err != nil {
		return ""
	}
	return parse.Path
}

func HasWhitespace(s string) bool {
	return regexp.MustCompile(`\s`).MatchString(s)
}

// IsValidCronExpression verify cronExpression and returns boolean
func IsValidCronExpression(cronExpr string) bool {
	// Parse the cron expression
	_, err := cron.ParseStandard(cronExpr)
	return err == nil
}

func ParseDuration(durationStr string) (time.Duration, error) {
	if durationStr == "" {
		return 0, nil
	}
	duration, err := time.ParseDuration(durationStr)
	if err != nil {
		return 0, err
	}
	return duration, nil
}

// ParseRanges converts a list of range strings to a slice of integers
func ParseRanges(rangeStrings []string) ([]int, error) {
	var result []int

	for _, rs := range rangeStrings {
		// Check if the string contains a range (indicated by a hyphen)
		if strings.Contains(rs, "-") {
			// Split the range string by the delimiter (hyphen)
			parts := strings.Split(rs, "-")
			if len(parts) != 2 {
				return nil, fmt.Errorf("invalid range format: %s", rs)
			}

			// Convert the start and end of the range to integers
			start, err := strconv.Atoi(strings.TrimSpace(parts[0]))
			if err != nil {
				return nil, fmt.Errorf("invalid start value in range: %s", rs)
			}

			end, err := strconv.Atoi(strings.TrimSpace(parts[1]))
			if err != nil {
				return nil, fmt.Errorf("invalid end value in range: %s", rs)
			}

			// Ensure the start is less than or equal to the end
			if start > end {
				return nil, fmt.Errorf("start value is greater than end value in range: %s", rs)
			}

			// Append all integers in the range to the result slice
			for i := start; i <= end; i++ {
				result = append(result, i)
			}
		} else {
			// If it's a single integer, convert it directly
			num, err := strconv.Atoi(strings.TrimSpace(rs))
			if err != nil {
				return nil, fmt.Errorf("invalid integer value: %s", rs)
			}
			result = append(result, num)
		}
	}
	return result, nil
}

// ValidateEndpoint checks if the endpoint is a valid URL/IP/host with optional port,
// and ensures it does not end with a trailing slash.
func ValidateEndpoint(endpoint string) error {
	if endpoint == "" {
		return errors.New("endpoint cannot be empty")
	}

	// Reject trailing slash (landing path)
	if strings.HasSuffix(endpoint, "/") {
		return fmt.Errorf("endpoint must not end with '/' : %s", endpoint)
	}

	u, err := url.Parse(endpoint)
	if err != nil {
		return fmt.Errorf("invalid endpoint: %w", err)
	}

	if u.Scheme == "" {
		return fmt.Errorf("missing scheme (http/https) in endpoint: %s", endpoint)
	}

	// Must have host
	if u.Host == "" {
		return fmt.Errorf("missing host in endpoint: %s", endpoint)
	}

	host, _, err := net.SplitHostPort(u.Host)
	if err != nil {
		// If no port, Host is just the hostname/IP
		host = u.Host
	}

	if ip := net.ParseIP(host); ip == nil {
		if err = validateHostname(host); err != nil {
			return fmt.Errorf("invalid host: %w", err)
		}
	}

	return nil
}

// validateHostname ensures the hostname follows DNS rules
func validateHostname(host string) error {
	if len(host) == 0 || len(host) > 253 {
		return errors.New("hostname length invalid")
	}
	labels := strings.Split(host, ".")
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 {
			return fmt.Errorf("invalid label length: %s", label)
		}
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return fmt.Errorf("label cannot start/end with hyphen: %s", label)
		}
	}
	return nil
}
