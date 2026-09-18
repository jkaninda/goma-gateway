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
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Removed keys are reported rather than ignored.
//
// Go's YAML decoder drops a key it does not recognise, so deleting the struct
// field alone would turn every removed key into a silent no-op. Two of them
// invert their replacement's meaning — `disableHostForwarding: true` becomes
// `forwardHostHeaders: false`, and `disabled: true` becomes `enabled: false` —
// so a configuration that still sets them would start, report nothing, and do
// the opposite of what it says. The gateway refuses to start instead, naming
// the key, where it is, and what to use in its place.
//
// yaml.v3's KnownFields would reject unknown keys generically, but the message
// ("field destination not found in type internal.Route") says nothing about the
// replacement, and it cannot reach a middleware `rule`, which is decoded
// separately per middleware type.

// removedKey describes what replaced one key removed in v1.0. The key itself is
// the map key it is stored under, so it is never spelled twice.
type removedKey struct {
	// replacement is what to use instead, ready to be read as a sentence
	// fragment after "use".
	replacement string
	// note carries anything the operator has to change beyond the name.
	note string
}

// describe renders the advice for one removed key as it appears in the report.
func (r removedKey) describe(key string) string {
	msg := fmt.Sprintf("`%s` was removed in v1.0", key)
	if r.replacement != "" {
		// A replacement naming a middleware rather than a key reads as prose,
		// so it is not quoted as one.
		if strings.Contains(r.replacement, " ") {
			msg += ", use " + r.replacement
		} else {
			msg += fmt.Sprintf(", use `%s`", r.replacement)
		}
	}
	if r.note != "" {
		msg += " (" + r.note + ")"
	}
	return msg
}

const keyInsecureSkipVerify = "insecureSkipVerify"

// Removed keys by the block they appear in.
var (
	removedTopLevelKeys = map[string]removedKey{
		"certificateManager": {replacement: "certManager"},
	}

	removedGatewayKeys = map[string]removedKey{
		"readTimeout":      {replacement: "timeouts.read"},
		"writeTimeout":     {replacement: "timeouts.write"},
		"idleTimeout":      {replacement: "timeouts.idle"},
		"enableMetrics":    {replacement: "monitoring.enableMetrics"},
		"errorInterceptor": {replacement: "the errorInterceptor middleware"},
		"cors":             {replacement: "the responseHeaders middleware"},
	}

	removedGatewayTLSKeys = map[string]removedKey{
		"keys": {replacement: "certificates"},
	}

	removedRouteKeys = map[string]removedKey{
		"destination":         {replacement: "target"},
		"disabled":            {replacement: "enabled", note: "the sense is inverted: disabled: true becomes enabled: false"},
		"blockCommonExploits": {replacement: "security.enableExploitProtection"},
		"disableHostForwarding": {replacement: "security.forwardHostHeaders",
			note: "the sense is inverted: disableHostForwarding: true becomes forwardHostHeaders: false"},
		keyInsecureSkipVerify: {replacement: "security.tls." + keyInsecureSkipVerify},
		"cors":                {replacement: "the responseHeaders middleware"},
		"errorInterceptor":    {replacement: "the errorInterceptor middleware"},
	}

	removedRouteSecurityTLSKeys = map[string]removedKey{
		"SkipVerification": {replacement: keyInsecureSkipVerify},
	}

	removedRuleKeys = map[MiddlewareType]map[string]removedKey{
		JWTAuth: {
			"alg":            {replacement: "algorithms", note: "a list, e.g. algorithms: [\"HS256\"]"},
			"forwardHeaders": {replacement: "forward.headers"},
		},
		forwardAuth: {
			"enableHostForwarding": {replacement: "forwardHostHeaders"},
			"skipInsecureVerify":   {replacement: keyInsecureSkipVerify},
		},
		OIDC: {
			"redirectUrl":  {replacement: "callbackPath", note: "the full URL is now derived from the request"},
			"redirectPath": {replacement: "postLoginRedirect"},
			"cookiePath":   {replacement: "session.cookie.path"},
			"state":        {note: "the state is now random per login; delete the key"},
		},
		errorInterceptor: {
			"code":   {replacement: "statusCode"},
			"status": {replacement: "statusCode"},
		},
	}

	// removedMiddlewareTypes are `type:` values that no longer resolve.
	removedMiddlewareTypes = map[string]removedKey{
		"oauth":  {replacement: "type: oidc"},
		"oauth2": {replacement: "type: oidc"},
	}

	// jwtTypes and oidcTypes are the spellings each middleware accepts, mapped
	// to the canonical type its rule keys are listed under.
	middlewareTypeAliases = map[MiddlewareType]MiddlewareType{
		JWTAuth:           JWTAuth,
		JWTAuthMiddleware: JWTAuth,
		OIDC:              OIDC,
		forwardAuth:       forwardAuth,
		errorInterceptor:  errorInterceptor,
	}
)

// configFinding is one removed key found at one place in a file.
type configFinding struct {
	// where locates the key for the operator: "gateway.routes[2] (api)".
	where string
	line  int
	// key is the key as it was written, and removed is what replaced it.
	key     string
	removed removedKey
}

// checkRemovedKeys reports every removed key in a full gateway configuration
// document. A nil error means the document uses none of them.
func checkRemovedKeys(source string, buf []byte) error {
	var doc yaml.Node
	if err := yaml.Unmarshal(buf, &doc); err != nil {
		// Let the real decoder report the syntax error with its own message.
		return nil
	}
	root := documentRoot(&doc)
	if root == nil {
		return nil
	}

	var findings []configFinding
	findings = append(findings, scanMapping(root, "", removedTopLevelKeys)...)

	if gateway := mappingValue(root, "gateway"); gateway != nil {
		findings = append(findings, scanMapping(gateway, "gateway", removedGatewayKeys)...)
		if tls := mappingValue(gateway, "tls"); tls != nil {
			findings = append(findings, scanMapping(tls, "gateway.tls", removedGatewayTLSKeys)...)
		}
		findings = append(findings, scanRoutes(mappingValue(gateway, "routes"), "gateway.routes")...)
	}
	// An extra-config file holds bare `routes:` and `middlewares:` lists.
	findings = append(findings, scanRoutes(mappingValue(root, "routes"), "routes")...)
	findings = append(findings, scanMiddlewares(mappingValue(root, "middlewares"), "middlewares")...)

	return findingsError(source, findings)
}

// scanRoutes checks every route in a sequence.
func scanRoutes(seq *yaml.Node, path string) []configFinding {
	if seq == nil || seq.Kind != yaml.SequenceNode {
		return nil
	}
	var findings []configFinding
	for i, route := range seq.Content {
		if route.Kind != yaml.MappingNode {
			continue
		}
		where := fmt.Sprintf("%s[%d]", path, i)
		if name := scalarValue(route, "name"); name != "" {
			where = fmt.Sprintf("%s[%d] (%s)", path, i, name)
		}
		findings = append(findings, scanMapping(route, where, removedRouteKeys)...)
		if security := mappingValue(route, "security"); security != nil {
			if tls := mappingValue(security, "tls"); tls != nil {
				findings = append(findings, scanMapping(tls, where+".security.tls", removedRouteSecurityTLSKeys)...)
			}
		}
	}
	return findings
}

// scanMiddlewares checks every middleware's type and rule.
func scanMiddlewares(seq *yaml.Node, path string) []configFinding {
	if seq == nil || seq.Kind != yaml.SequenceNode {
		return nil
	}
	var findings []configFinding
	for i, middleware := range seq.Content {
		if middleware.Kind != yaml.MappingNode {
			continue
		}
		where := fmt.Sprintf("%s[%d]", path, i)
		if name := scalarValue(middleware, "name"); name != "" {
			where = fmt.Sprintf("%s[%d] (%s)", path, i, name)
		}

		rawType := scalarValue(middleware, "type")
		if removed, ok := removedMiddlewareTypes[strings.ToLower(rawType)]; ok {
			line := middleware.Line
			if valueNode := mappingValue(middleware, "type"); valueNode != nil {
				line = valueNode.Line
			}
			findings = append(findings, configFinding{
				where: where, line: line, key: "type: " + rawType, removed: removed,
			})
		}

		rule := mappingValue(middleware, "rule")
		if rule == nil || rule.Kind != yaml.MappingNode {
			continue
		}
		canonical, ok := middlewareTypeAliases[MiddlewareType(rawType)]
		if !ok {

			if _, removed := removedMiddlewareTypes[strings.ToLower(rawType)]; removed {
				canonical = OIDC
			} else {
				continue
			}
		}
		findings = append(findings, scanMapping(rule, where+".rule", removedRuleKeys[canonical])...)

		// errorInterceptor lists its removed keys one level deeper, per error.
		if canonical == errorInterceptor {
			if errs := mappingValue(rule, "errors"); errs != nil && errs.Kind == yaml.SequenceNode {
				for j, entry := range errs.Content {
					if entry.Kind != yaml.MappingNode {
						continue
					}
					findings = append(findings, scanMapping(entry,
						fmt.Sprintf("%s.rule.errors[%d]", where, j), removedRuleKeys[errorInterceptor])...)
				}
			}
		}
	}
	return findings
}

// scanMapping reports the removed keys present in one mapping node.
func scanMapping(node *yaml.Node, where string, removed map[string]removedKey) []configFinding {
	if node == nil || node.Kind != yaml.MappingNode || len(removed) == 0 {
		return nil
	}
	var findings []configFinding
	for i := 0; i+1 < len(node.Content); i += 2 {
		key := node.Content[i]
		if key.Kind != yaml.ScalarNode {
			continue
		}
		if entry, ok := removed[key.Value]; ok {
			findings = append(findings, configFinding{where: where, line: key.Line, key: key.Value, removed: entry})
		}
	}
	return findings
}

// findingsError renders the findings as one error listing every removed key, so
// a migration takes one pass rather than one restart per key.
func findingsError(source string, findings []configFinding) error {
	if len(findings) == 0 {
		return nil
	}
	sort.SliceStable(findings, func(i, j int) bool { return findings[i].line < findings[j].line })

	var b strings.Builder
	fmt.Fprintf(&b, "%s uses %s removed in v1.0:", source, plural(len(findings), "a configuration key", "configuration keys"))
	for _, f := range findings {
		b.WriteString("\n  ")
		if f.where != "" {
			fmt.Fprintf(&b, "line %d, %s: %s", f.line, f.where, f.removed.describe(f.key))
		} else {
			fmt.Fprintf(&b, "line %d: %s", f.line, f.removed.describe(f.key))
		}
	}
	b.WriteString("\n\nSee https://jkaninda.github.io/goma-gateway/upgrade/v1.0 for the full migration guide.")
	return fmt.Errorf("%s", b.String())
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// documentRoot unwraps the document node a full-file parse produces.
func documentRoot(node *yaml.Node) *yaml.Node {
	if node == nil {
		return nil
	}
	if node.Kind == yaml.DocumentNode {
		if len(node.Content) == 0 {
			return nil
		}
		node = node.Content[0]
	}
	if node.Kind != yaml.MappingNode {
		return nil
	}
	return node
}

// mappingValue returns the value node for a key in a mapping.
func mappingValue(node *yaml.Node, key string) *yaml.Node {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i].Kind == yaml.ScalarNode && node.Content[i].Value == key {
			return node.Content[i+1]
		}
	}
	return nil
}

// scalarValue returns a mapping's scalar value for a key, or "".
func scalarValue(node *yaml.Node, key string) string {
	value := mappingValue(node, key)
	if value == nil || value.Kind != yaml.ScalarNode {
		return ""
	}
	return value.Value
}
