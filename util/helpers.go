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
	"fmt"
	"github.com/jkaninda/logger"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/robfig/cron/v3"
)

var envPattern = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

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

func Slug(text string) string {
	// Convert to lowercase
	text = strings.ToLower(text)

	// Replace spaces and special characters with hyphens
	re := regexp.MustCompile(`\W+`)
	text = re.ReplaceAllString(text, "-")

	// Remove leading and trailing hyphens
	text = strings.Trim(text, "-")

	return text
}

func AddPrefixPath(prefix string, paths []string) []string {
	for i := range paths {
		paths[i] = ParseURLPath(prefix + paths[i])
	}
	return paths

}
func TruncateText(text string, limit int) string {
	if len(text) > limit {
		return text[:limit] + "..."
	}
	return text
}

// ConvertBytes converts bytes to a human-readable string with the appropriate unit (bytes, MiB, or GiB).
func ConvertBytes(bytes uint64) string {
	const (
		MiB = 1024 * 1024
		GiB = MiB * 1024
	)
	switch {
	case bytes >= GiB:
		return fmt.Sprintf("%.2f GiB", float64(bytes)/float64(GiB))
	case bytes >= MiB:
		return fmt.Sprintf("%.2f MiB", float64(bytes)/float64(MiB))
	default:
		return fmt.Sprintf("%d bytes", bytes)
	}
}

// ConvertToBytes converts a string with a size suffix (e.g., "1M", "1Mi") to bytes.
func ConvertToBytes(input string) (int64, error) {
	// Define the mapping for binary (Mi) and decimal (M) units
	binaryUnits := map[string]int64{
		"Ki": 1024,
		"Mi": 1024 * 1024,
		"Gi": 1024 * 1024 * 1024,
		"Ti": 1024 * 1024 * 1024 * 1024,
		"Pi": 1024 * 1024 * 1024 * 1024 * 1024,
		"Ei": 1024 * 1024 * 1024 * 1024 * 1024 * 1024,
	}
	decimalUnits := map[string]int64{
		"K": 1000,
		"M": 1000 * 1000,
		"G": 1000 * 1000 * 1000,
		"T": 1000 * 1000 * 1000 * 1000,
		"P": 1000 * 1000 * 1000 * 1000 * 1000,
		"E": 1000 * 1000 * 1000 * 1000 * 1000 * 1000,
	}

	// Extract the numeric part and the unit
	var numberPart string
	var unitPart string

	for i, r := range input {
		if r < '0' || r > '9' {
			numberPart = input[:i]
			unitPart = input[i:]
			break
		}
	}

	// Handle case where no valid unit is found
	if unitPart == "" {
		return 0, fmt.Errorf("invalid format: no unit provided")
	}

	// Convert the numeric part to an integer
	value, err := strconv.ParseInt(numberPart, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid number format: %w", err)
	}

	// Determine the multiplier
	var multiplier int64
	if strings.HasSuffix(unitPart, "i") {
		// Binary units
		multiplier, err = findMultiplier(unitPart, binaryUnits)
	} else {
		// Decimal units
		multiplier, err = findMultiplier(unitPart, decimalUnits)
	}

	if err != nil {
		return 0, err
	}

	// Calculate the bytes
	return value * multiplier, nil
}

// Helper function to find the multiplier for a given unit
func findMultiplier(unit string, units map[string]int64) (int64, error) {
	multiplier, ok := units[unit]
	if !ok {
		return 0, fmt.Errorf("invalid unit: %s", unit)
	}
	return multiplier, nil
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

// RemoveDuplicates Duplicated
func RemoveDuplicates[T comparable](elements []T) []T {
	encountered := make(map[T]bool)
	result := make([]T, 0, len(elements))

	for _, elem := range elements {
		if !encountered[elem] {
			encountered[elem] = true
			result = append(result, elem)
		}
	}

	return result
}

// ReplaceEnvVars replaces ${VAR} with the environment variable value if present
func ReplaceEnvVars(s string) string {
	if !envPattern.MatchString(s) {
		logger.Debug("No env pattern found")
		return s
	}
	return envPattern.ReplaceAllStringFunc(s, func(match string) string {
		name := envPattern.FindStringSubmatch(match)[1]
		if val, ok := os.LookupEnv(name); ok {
			return val
		}
		logger.Error("No environment variable found", "env", name)
		return match
	})
}
