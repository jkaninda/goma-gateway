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
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	goutils "github.com/jkaninda/go-utils"
	"github.com/jkaninda/goma-gateway/internal/middlewares"
	"gopkg.in/yaml.v3"
)

var yamlUnknownField = regexp.MustCompile(`^(line \d+: )?field (\S+) not found in type`)

// ruleStruct returns a pointer to the rule structure a middleware type is
// decoded into when it is applied, or nil when the type takes no rule.
func ruleStruct(t MiddlewareType) any {
	switch t {
	case AccessMiddleware:
		return &AccessRuleMiddleware{}
	case rateLimit, MiddlewareType(strings.ToLower(string(rateLimit))):
		return &RateLimitRuleMiddleware{}
	case accessPolicy:
		return &AccessPolicyRuleMiddleware{}
	case addPrefix:
		return &AddPrefixRuleMiddleware{}
	case redirect:
		return &RedirectRuleMiddleware{}
	case redirectScheme:
		return &RedirectSchemeRuleMiddleware{}
	case rewriteRegex:
		return &RewriteRegexRuleMiddleware{}
	case stripQuery:
		return &StripQueryRuleMiddleware{}
	case redirectRegex:
		return &RedirectRegexRuleMiddleware{}
	case httpCache:
		return &httpCacheRule{}
	case bodyLimit:
		return &BodyLimitRuleMiddleware{}
	case userAgentBlock:
		return &UserAgentBlockRuleMiddleware{}
	case geoBlock:
		return &GeoBlockRuleMiddleware{}
	case accessLog:
		return &LogEnrichRule{}
	case responseHeaders:
		return &ResponseHeader{}
	case requestHeaders:
		return &RequestHeader{}
	case errorInterceptor:
		return &middlewares.RouteErrorInterceptor{}
	case BasicAuth, BasicAuthMiddleware:
		return &BasicRuleMiddleware{}
	case LDAPAuthMiddleware, LDAPAuth:
		return &LdapRuleMiddleware{}
	case JWTAuth, JWTAuthMiddleware:
		return &JWTRuleMiddleware{}
	case forwardAuth:
		return &ForwardAuthRuleMiddleware{}
	case OIDC:
		return &OIDCRuleMiddleware{}
	}
	return nil
}

// unknownKeys reports keys in a configuration document that the gateway does
// not recognize and would otherwise silently ignore. into is the document's
// top-level type, e.g. &GatewayConfig{}.
func unknownKeys(buf []byte, into any) []string {
	var found []string
	dec := yaml.NewDecoder(bytes.NewReader(buf))
	dec.KnownFields(true)
	var typeErr *yaml.TypeError
	if err := dec.Decode(into); errors.As(err, &typeErr) {
		for _, e := range typeErr.Errors {
			if m := yamlUnknownField.FindStringSubmatch(e); m != nil {
				found = append(found, fmt.Sprintf("%sunknown key %q", m[1], m[2]))
			}
		}
	}

	// Middleware rules are decoded per type after loading, so check them
	// against the structure each type is applied with.
	var doc struct {
		Middlewares []struct {
			Name string         `yaml:"name"`
			Type MiddlewareType `yaml:"type"`
			Rule any            `yaml:"rule"`
		} `yaml:"middlewares"`
	}
	if yaml.Unmarshal(buf, &doc) != nil {
		return found
	}
	for _, mid := range doc.Middlewares {
		found = append(found, unknownRuleKeys(mid.Name, mid.Type, mid.Rule)...)
	}
	return found
}

func unknownRuleKeys(name string, t MiddlewareType, rule any) []string {
	target := ruleStruct(t)
	if target == nil || rule == nil {
		return nil
	}
	if s, ok := rule.(string); ok && s != "" {
		return nil // encrypted rule, decoded after decryption
	}
	data, err := json.Marshal(rule)
	if err != nil {
		return nil
	}
	var found []string
	for {
		dec := json.NewDecoder(bytes.NewReader(data))
		dec.DisallowUnknownFields()
		err := dec.Decode(target)
		if err == nil || !strings.HasPrefix(err.Error(), "json: unknown field ") {
			return found
		}
		field := strings.Trim(strings.TrimPrefix(err.Error(), "json: unknown field "), `"`)
		found = append(found, fmt.Sprintf("middleware %q (%s): rule field %q is not a %s option", name, t, field, t))
		// The decoder stops at the first unknown field; drop it to find the next.
		if data, err = dropJSONKey(data, field); err != nil {
			return found
		}
		target = ruleStruct(t)
	}
}

// dropJSONKey removes the first occurrence of key from a JSON object at any
// depth, so a strict decode can continue past it.
func dropJSONKey(data []byte, key string) ([]byte, error) {
	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		return nil, err
	}
	if !deleteKey(v, key) {
		return nil, errors.New("key not found")
	}
	return json.Marshal(v)
}

func deleteKey(v any, key string) bool {
	switch t := v.(type) {
	case map[string]any:
		if _, ok := t[key]; ok {
			delete(t, key)
			return true
		}
		for _, child := range t {
			if deleteKey(child, key) {
				return true
			}
		}
	case []any:
		for _, child := range t {
			if deleteKey(child, key) {
				return true
			}
		}
	}
	return false
}

// warnUnknownKeys logs the unknown keys in a configuration document. Loading
// continues, so a configuration that worked before keeps working.
func warnUnknownKeys(source string, buf []byte, into any) {
	for _, k := range unknownKeys(buf, into) {
		logger.Warn("Unknown configuration key is ignored", "source", source, "key", k)
	}
}

// ruleError decodes a middleware's rule the way it is applied and runs the
// type's own validation, reporting what would otherwise only be logged when
// the route is built.
func ruleError(mid Middleware) error {
	target := ruleStruct(mid.Type)
	if target == nil {
		return nil
	}
	if _, encrypted := mid.Rule.(string); encrypted {
		return nil
	}
	if err := goutils.DeepCopy(target, mid.Rule); err != nil {
		return err
	}
	switch v := target.(type) {
	case *ResponseHeader:
		v.Name = mid.Name
		return v.validate(&Route{})
	case interface{ validate() error }:
		return v.validate()
	case interface{ Validate() error }:
		return v.Validate()
	}
	return nil
}
