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
	"net/url"
	"strings"
)

// Cors defines the configuration structure for Cross-Origin Resource Sharing (CORS) settings
type Cors struct {
	// Enabled indicates whether CORS is enabled for the resource
	Enabled bool `yaml:"enabled"`
	// Origins specify which origins are allowed to access the resource.
	// Examples:
	// - http://localhost:80
	// - https://example.com
	// - * (wildcard - allows all origins, cannot be used with AllowCredentials=true)
	Origins []string `yaml:"origins"`

	// AllowedHeaders defines which request headers are permitted in actual requests
	AllowedHeaders []string `yaml:"allowedHeaders"`

	// Headers contains custom headers to be set in the response
	// Deprecated, use responseHeaders middleware type
	Headers map[string]string `yaml:"headers"`

	// ExposeHeaders indicates which response headers can be exposed to the client
	ExposeHeaders []string `yaml:"exposeHeaders"`

	// MaxAge defines how long (in seconds) the results of a preflight request can be cached
	// Default: 86400 (24 hours), Maximum: 86400 (some browsers enforce this)
	MaxAge int `yaml:"maxAge"`

	// AllowMethods lists the HTTP methods permitted for cross-origin requests
	AllowMethods []string `yaml:"allowMethods"`

	// AllowCredentials indicates whether the response can include credentials (cookies, HTTP auth)
	AllowCredentials bool `yaml:"allowCredentials"`
}

func (cors *Cors) isZero() bool {
	return len(cors.Origins) == 0 &&
		len(cors.AllowedHeaders) == 0 &&
		len(cors.Headers) == 0 &&
		len(cors.ExposeHeaders) == 0 &&
		len(cors.AllowMethods) == 0 &&
		!cors.AllowCredentials &&
		cors.MaxAge == 0
}

func (cors *Cors) validate() error {
	// If CORS is not enabled, skip validation
	if !cors.Enabled {
		return nil
	}

	if cors.isZero() {
		return fmt.Errorf("CORS is enabled but has no configuration")
	}

	// Validate Origins
	if err := cors.validateOrigins(); err != nil {
		return err
	}

	// Validate Methods
	if err := cors.validateMethods(); err != nil {
		return err
	}

	// Validate Headers
	if err := cors.validateHeaders(); err != nil {
		return err
	}

	// Validate MaxAge
	if err := cors.validateMaxAge(); err != nil {
		return err
	}

	// Validate credential configuration
	if err := cors.validateCredentials(); err != nil {
		return err
	}
	return nil
}

func (cors *Cors) validateOrigins() error {
	if len(cors.Origins) == 0 {
		return fmt.Errorf("CORS origins cannot be empty when CORS is enabled")
	}

	for i, origin := range cors.Origins {
		// Trim whitespace
		origin = strings.TrimSpace(origin)
		cors.Origins[i] = origin

		if origin == "" {
			return fmt.Errorf("CORS origin at index %d is empty", i)
		}

		// Check for wildcard
		if origin == "*" {

			if len(cors.Origins) > 1 {
				return fmt.Errorf("wildcard '*' origin cannot be combined with other origins")
			}
			continue
		}

		// Validate origin format (must be a valid URL with scheme and host)
		if !strings.Contains(origin, "://") {
			return fmt.Errorf("invalid origin format '%s': must include scheme (e.g., https://example.com)", origin)
		}

		// Parse as URL to validate
		parsedURL, err := url.Parse(origin)
		if err != nil {
			return fmt.Errorf("invalid origin URL '%s': %w", origin, err)
		}

		// Check for valid scheme
		if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
			return fmt.Errorf("invalid origin scheme in '%s': only http and https are allowed", origin)
		}

		// Origin should not have path, query, or fragment
		if parsedURL.Path != "" && parsedURL.Path != "/" {
			return fmt.Errorf("origin '%s' should not contain a path", origin)
		}
		if parsedURL.RawQuery != "" {
			return fmt.Errorf("origin '%s' should not contain query parameters", origin)
		}
		if parsedURL.Fragment != "" {
			return fmt.Errorf("origin '%s' should not contain a fragment", origin)
		}

		// Normalize: remove trailing slash
		if strings.HasSuffix(origin, "/") {
			cors.Origins[i] = strings.TrimSuffix(origin, "/")
		}
	}

	// Check for duplicate origins
	originSet := make(map[string]bool)
	for _, origin := range cors.Origins {
		if originSet[origin] {
			return fmt.Errorf("duplicate origin found: %s", origin)
		}
		originSet[origin] = true
	}
	return nil
}

func (cors *Cors) validateMethods() error {
	if len(cors.AllowMethods) == 0 {
		return nil
	}

	validMethods := map[string]bool{
		"GET":     true,
		"POST":    true,
		"PUT":     true,
		"PATCH":   true,
		"DELETE":  true,
		"HEAD":    true,
		"OPTIONS": true,
		"CONNECT": true,
		"TRACE":   true,
	}

	methodSet := make(map[string]bool)
	for i, method := range cors.AllowMethods {
		// Normalize to uppercase
		method = strings.ToUpper(strings.TrimSpace(method))
		cors.AllowMethods[i] = method

		if method == "" {
			return fmt.Errorf("empty HTTP method in allowMethods at index %d", i)
		}

		if !validMethods[method] {
			return fmt.Errorf("invalid HTTP method '%s' in allowMethods", method)
		}

		// Check for duplicates
		if methodSet[method] {
			return fmt.Errorf("duplicate method '%s' in allowMethods", method)
		}
		methodSet[method] = true
	}

	if methodSet["OPTIONS"] {
		return fmt.Errorf("OPTIONS method should not be explicitly listed in allowMethods (handled automatically)")
	}

	return nil
}

func (cors *Cors) validateHeaders() error {
	// Validate AllowedHeaders
	if len(cors.AllowedHeaders) > 0 {
		headerSet := make(map[string]bool)
		for i, header := range cors.AllowedHeaders {
			header = strings.TrimSpace(header)
			// Normalize to lowercase for comparison (HTTP headers are case-insensitive)
			normalizedHeader := strings.ToLower(header)
			cors.AllowedHeaders[i] = header

			if header == "" {
				return fmt.Errorf("empty header in allowedHeaders at index %d", i)
			}

			// Check for duplicates
			if headerSet[normalizedHeader] {
				return fmt.Errorf("duplicate header '%s' in allowedHeaders", header)
			}
			headerSet[normalizedHeader] = true

			// Validate header name format (basic check)
			if !isValidHeaderName(header) {
				return fmt.Errorf("invalid header name '%s' in allowedHeaders", header)
			}
		}
	}

	// Validate ExposeHeaders
	if len(cors.ExposeHeaders) > 0 {
		headerSet := make(map[string]bool)
		for i, header := range cors.ExposeHeaders {
			header = strings.TrimSpace(header)
			normalizedHeader := strings.ToLower(header)
			cors.ExposeHeaders[i] = header

			if header == "" {
				return fmt.Errorf("empty header in exposeHeaders at index %d", i)
			}

			// Check for duplicates
			if headerSet[normalizedHeader] {
				return fmt.Errorf("duplicate header '%s' in exposeHeaders", header)
			}
			headerSet[normalizedHeader] = true

			// Wildcard '*' cannot be used with credentials
			if header == "*" && cors.AllowCredentials {
				return fmt.Errorf("wildcard '*' in exposeHeaders cannot be used when allowCredentials is true")
			}

			if header != "*" && !isValidHeaderName(header) {
				return fmt.Errorf("invalid header name '%s' in exposeHeaders", header)
			}
		}
	}

	if len(cors.Headers) > 0 {
		logger.Warn("CORS 'headers' field is deprecated, use responseHeaders middleware instead")
	}

	return nil
}

func (cors *Cors) validateMaxAge() error {
	if cors.MaxAge < 0 {
		return fmt.Errorf("maxAge cannot be negative (got %d)", cors.MaxAge)
	}
	if cors.MaxAge > 86400 {
		return fmt.Errorf("maxAge exceeds browser maximum of 86400 seconds (got %d)", cors.MaxAge)
	}
	return nil
}

func (cors *Cors) validateCredentials() error {
	if !cors.AllowCredentials {
		return nil
	}
	// AllowCredentials=true cannot be used with wildcard origin
	for _, origin := range cors.Origins {
		if origin == "*" {
			return fmt.Errorf("allowCredentials cannot be true when using wildcard '*' origin")
		}
	}

	// AllowCredentials=true requires specific origins
	if len(cors.Origins) == 0 {
		return fmt.Errorf("allowCredentials requires specific origins (cannot be empty)")
	}

	return nil
}

// isValidHeaderName checks if a header name is valid according to HTTP specifications
func isValidHeaderName(name string) bool {
	if name == "" {
		return false
	}

	// Header names must be tokens (RFC 7230)
	// token = 1*tchar
	// tchar = "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" / "-" / "." /
	//         "0"-"9" / "A"-"Z" / "^" / "_" / "`" / "a"-"z" / "|" / "~"
	for _, ch := range name {
		if !isTokenChar(ch) {
			return false
		}
	}
	return true
}

func isTokenChar(ch rune) bool {
	return (ch >= 'a' && ch <= 'z') ||
		(ch >= 'A' && ch <= 'Z') ||
		(ch >= '0' && ch <= '9') ||
		ch == '!' || ch == '#' || ch == '$' || ch == '%' || ch == '&' ||
		ch == '\'' || ch == '*' || ch == '+' || ch == '-' || ch == '.' ||
		ch == '^' || ch == '_' || ch == '`' || ch == '|' || ch == '~'
}
