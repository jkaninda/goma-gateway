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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

const (
	// DefaultArraySeparator joins multi-valued claims such as "groups".
	DefaultArraySeparator = ","
	// DefaultMaxClaimValueBytes bounds a single projected value. Most upstream
	// servers reject a request whose total header block exceeds 8KB, so a
	// group-heavy token must not be able to make every request unroutable.
	DefaultMaxClaimValueBytes = 4096
	// encodingHeaderSuffix names the companion header that tells the upstream a
	// value was base64-encoded because it contained non-ASCII characters.
	encodingHeaderSuffix = "-Encoding"

	// ClaimEncodingAuto base64-encodes values that are not pure ASCII.
	ClaimEncodingAuto = "auto"
	// ClaimEncodingRaw passes values through untouched (control characters are
	// still removed).
	ClaimEncodingRaw = "raw"
)

// ClaimMapper projects verified identity claims onto the upstream request as
// headers, query parameters and cookies. It is shared by every middleware that
// authenticates a user (JWT, OAuth/OIDC) so a claim path means the same thing
// everywhere.
//
// A value is either a claim path with dot notation for nested objects
// ("resource_access.app.tenant") or a template interpolating several of them
// ("{{ .given_name }} {{ .family_name }}").
type ClaimMapper struct {
	// Headers, Query and Cookies map a destination key to a claim path or
	// template. Cookies are added to the upstream request only, never to the
	// client response.
	Headers map[string]string
	Query   map[string]string
	Cookies map[string]string

	// ArraySeparator joins array claims. Defaults to DefaultArraySeparator.
	ArraySeparator string

	// Encoding is ClaimEncodingAuto (default) or ClaimEncodingRaw. Header values
	// are restricted to ASCII by RFC 9110; "auto" base64-encodes anything else
	// and flags it with a "<Name>-Encoding: base64" companion header, so a user
	// whose display name is not ASCII does not silently reach the backend as
	// mojibake.
	Encoding string

	// MaxValueBytes bounds a single value. Defaults to DefaultMaxClaimValueBytes.
	MaxValueBytes int

	// StripInbound removes any client-supplied copy of every mapped key before
	// projecting. Nil means enabled. Disabling it lets a client forge its own
	// identity headers, so it is only safe when nothing but the gateway can
	// reach the upstream.
	StripInbound *bool

	// AccessTokenHeader and IDTokenHeader forward the raw tokens when set. The
	// value is the bare token except on "Authorization", where the header's own
	// grammar requires the "Bearer " prefix.
	AccessTokenHeader string
	IDTokenHeader     string
}

// Enabled reports whether the mapper has anything to project.
func (m *ClaimMapper) Enabled() bool {
	if m == nil {
		return false
	}
	return len(m.Headers) > 0 || len(m.Query) > 0 || len(m.Cookies) > 0 ||
		m.AccessTokenHeader != "" || m.IDTokenHeader != ""
}

func (m *ClaimMapper) separator() string {
	if m.ArraySeparator == "" {
		return DefaultArraySeparator
	}
	return m.ArraySeparator
}

func (m *ClaimMapper) maxValueBytes() int {
	if m.MaxValueBytes <= 0 {
		return DefaultMaxClaimValueBytes
	}
	return m.MaxValueBytes
}

func (m *ClaimMapper) stripsInbound() bool {
	return m.StripInbound == nil || *m.StripInbound
}

// Apply strips client-supplied copies of the mapped keys and projects the
// claims onto r. Claims that cannot be resolved leave the key absent, which is
// why stripping happens first and unconditionally.
func (m *ClaimMapper) Apply(r *http.Request, claims map[string]interface{}) {
	if !m.Enabled() {
		return
	}
	if m.stripsInbound() {
		m.Strip(r)
	}

	for name, expr := range m.Headers {
		value, ok := m.resolve(claims, expr)
		if !ok {
			continue
		}
		encoded, isEncoded, ok := m.encodeValue(value)
		if !ok {
			logger.Warn("Claim value too large to forward, header skipped",
				"header", name, "bytes", len(value), "limit", m.maxValueBytes())
			continue
		}
		r.Header.Set(name, encoded)
		if isEncoded {
			r.Header.Set(name+encodingHeaderSuffix, "base64")
		}
	}

	if len(m.Query) > 0 {
		query := r.URL.Query()
		for name, expr := range m.Query {
			value, ok := m.resolve(claims, expr)
			if !ok {
				continue
			}
			query.Set(name, value)
		}
		r.URL.RawQuery = query.Encode()
	}

	for name, expr := range m.Cookies {
		value, ok := m.resolve(claims, expr)
		if !ok {
			continue
		}
		// Percent-encode: cookie values may not carry ";", "," or spaces, and Go
		// would otherwise drop the whole cookie when writing it out.
		r.AddCookie(&http.Cookie{Name: name, Value: url.QueryEscape(value)})
	}
}

// Strip removes every mapped key that the client supplied. Without it a client
// can simply send "X-Auth-Email: admin@example.com" and impersonate anyone.
func (m *ClaimMapper) Strip(r *http.Request) {
	if m == nil {
		return
	}
	for name := range m.Headers {
		r.Header.Del(name)
		r.Header.Del(name + encodingHeaderSuffix)
	}
	if m.AccessTokenHeader != "" {
		r.Header.Del(m.AccessTokenHeader)
	}
	if m.IDTokenHeader != "" {
		r.Header.Del(m.IDTokenHeader)
	}
	if len(m.Query) > 0 {
		query := r.URL.Query()
		for name := range m.Query {
			query.Del(name)
		}
		r.URL.RawQuery = query.Encode()
	}
	deleteRequestCookies(r, m.Cookies)
}

// ForwardTokens attaches the raw tokens to the upstream request when the mapper
// is configured to do so.
func (m *ClaimMapper) ForwardTokens(r *http.Request, accessToken, idToken string) {
	if m == nil {
		return
	}
	if m.AccessTokenHeader != "" && accessToken != "" {
		r.Header.Set(m.AccessTokenHeader, bearerValue(m.AccessTokenHeader, accessToken))
	}
	if m.IDTokenHeader != "" && idToken != "" {
		r.Header.Set(m.IDTokenHeader, bearerValue(m.IDTokenHeader, idToken))
	}
}

func bearerValue(header, token string) string {
	if strings.EqualFold(header, "Authorization") {
		return "Bearer " + token
	}
	return token
}

// resolve turns a claim path or template into a string. It reports false when
// nothing resolved, so the caller can leave the key absent rather than
// forwarding an empty value that an upstream might read as "anonymous".
func (m *ClaimMapper) resolve(claims map[string]interface{}, expr string) (string, bool) {
	var value string
	if strings.Contains(expr, "{{") {
		value = m.renderTemplate(claims, expr)
	} else {
		claimValue, err := ExtractClaim(claims, expr)
		if err != nil {
			logger.Debug("Claim not found, key not forwarded", "claim", expr, "error", err)
			return "", false
		}
		value = FormatClaimValue(claimValue, m.separator())
	}

	value = sanitizeValue(value)
	if value == "" {
		return "", false
	}
	return value, true
}

// renderTemplate interpolates "{{ .claim.path }}" placeholders. Unresolved
// placeholders render as empty rather than as an error marker so a partially
// populated token still yields a usable value.
func (m *ClaimMapper) renderTemplate(claims map[string]interface{}, expr string) string {
	var out strings.Builder
	rest := expr
	for {
		start := strings.Index(rest, "{{")
		if start < 0 {
			out.WriteString(rest)
			return out.String()
		}
		end := strings.Index(rest[start:], "}}")
		if end < 0 {
			out.WriteString(rest)
			return out.String()
		}
		end += start
		out.WriteString(rest[:start])

		path := strings.TrimSpace(rest[start+2 : end])
		path = strings.TrimPrefix(path, ".")
		if path != "" {
			if claimValue, err := ExtractClaim(claims, path); err == nil {
				out.WriteString(FormatClaimValue(claimValue, m.separator()))
			} else {
				logger.Debug("Claim not found while rendering template", "claim", path, "template", expr)
			}
		}
		rest = rest[end+2:]
	}
}

// encodeValue applies the configured encoding and enforces the size bound.
func (m *ClaimMapper) encodeValue(value string) (string, bool, bool) {
	if isASCII(value) || m.Encoding == ClaimEncodingRaw {
		if len(value) > m.maxValueBytes() {
			return "", false, false
		}
		return value, false, true
	}
	encoded := base64.StdEncoding.EncodeToString([]byte(value))
	if len(encoded) > m.maxValueBytes() {
		return "", false, false
	}
	return encoded, true, true
}

// ExtractClaim reads a claim using dot notation for nested objects, e.g.
// "resource_access.myapp.tenant".
func ExtractClaim(claims map[string]interface{}, claimPath string) (interface{}, error) {
	if claimPath == "" {
		return nil, fmt.Errorf("empty claim path")
	}
	keys := strings.Split(claimPath, ".")
	var current interface{} = claims

	for i, key := range keys {
		object, ok := current.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("cannot traverse claim path at key '%s' (expected object, got %T)", key, current)
		}
		value, exists := object[key]
		if !exists {
			return nil, fmt.Errorf("claim key '%s' not found at path '%s'", key, strings.Join(keys[:i+1], "."))
		}
		current = value
	}
	return current, nil
}

// FormatClaimValue renders a claim value as a single string.
func FormatClaimValue(claimValue interface{}, separator string) string {
	if separator == "" {
		separator = DefaultArraySeparator
	}
	switch value := claimValue.(type) {
	case nil:
		return ""
	case string:
		return value
	case bool:
		return strconv.FormatBool(value)
	case float64:
		return strconv.FormatFloat(value, 'f', -1, 64)
	case float32:
		return strconv.FormatFloat(float64(value), 'f', -1, 32)
	case int:
		return strconv.Itoa(value)
	case int64:
		return strconv.FormatInt(value, 10)
	case json.Number:
		return value.String()
	case []interface{}:
		parts := make([]string, 0, len(value))
		for _, item := range value {
			parts = append(parts, FormatClaimValue(item, separator))
		}
		return strings.Join(parts, separator)
	case []string:
		return strings.Join(value, separator)
	case map[string]interface{}:
		// Nested objects are forwarded as compact JSON so an upstream can parse
		// them instead of receiving Go's map formatting.
		encoded, err := json.Marshal(value)
		if err != nil {
			return ""
		}
		return string(encoded)
	default:
		return fmt.Sprintf("%v", value)
	}
}

// sanitizeValue removes control characters. CR and LF in particular would let a
// claim an upstream identity provider lets users set (a display name, say)
// inject additional headers into the proxied request.
func sanitizeValue(value string) string {
	if !strings.ContainsFunc(value, isControl) {
		return strings.TrimSpace(value)
	}
	var out strings.Builder
	out.Grow(len(value))
	for _, r := range value {
		if isControl(r) {
			continue
		}
		out.WriteRune(r)
	}
	return strings.TrimSpace(out.String())
}

func isControl(r rune) bool {
	return r < 0x20 || r == 0x7f
}

func isASCII(value string) bool {
	for i := 0; i < len(value); i++ {
		if value[i] >= 0x80 {
			return false
		}
	}
	return true
}

// deleteRequestCookies rewrites the request's Cookie header without the named
// cookies.
func deleteRequestCookies(r *http.Request, names map[string]string) {
	if len(names) == 0 || r.Header.Get("Cookie") == "" {
		return
	}
	kept := make([]*http.Cookie, 0, len(r.Cookies()))
	for _, cookie := range r.Cookies() {
		if _, mapped := names[cookie.Name]; mapped {
			continue
		}
		kept = append(kept, cookie)
	}
	r.Header.Del("Cookie")
	for _, cookie := range kept {
		r.AddCookie(cookie)
	}
}

// claimsFromMap normalizes any claim carrier (jwt.MapClaims, decoded JSON) into
// a plain map.
func claimsFromMap(claims map[string]interface{}) map[string]interface{} {
	if claims == nil {
		return map[string]interface{}{}
	}
	return claims
}

// mergeClaims copies src over dst, so callers can layer claim sources in
// increasing order of precedence.
func mergeClaims(dst, src map[string]interface{}) map[string]interface{} {
	if dst == nil {
		dst = map[string]interface{}{}
	}
	for key, value := range src {
		dst[key] = value
	}
	return dst
}
