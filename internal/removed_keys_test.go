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
	"strings"
	"testing"
)

// Every key the v1.0 upgrade note promises is removed has to be rejected, not
// silently ignored — yaml.v3 drops unknown keys, so without the check a
// configuration that still sets `disableHostForwarding: true` would start and
// forward the host header it means to withhold.
func TestCheckRemovedKeysRejectsEveryRemovedKey(t *testing.T) {
	cases := []struct {
		name   string
		config string
		// want is a fragment of the message the operator should see.
		want string
	}{
		{"gateway certificateManager", "certificateManager:\n  acme:\n    email: a@b.c\n", "use `certManager`"},
		{"gateway readTimeout", "gateway:\n  readTimeout: 30\n", "use `timeouts.read`"},
		{"gateway writeTimeout", "gateway:\n  writeTimeout: 30\n", "use `timeouts.write`"},
		{"gateway idleTimeout", "gateway:\n  idleTimeout: 30\n", "use `timeouts.idle`"},
		{"gateway enableMetrics", "gateway:\n  enableMetrics: true\n", "use `monitoring.enableMetrics`"},
		{"gateway errorInterceptor", "gateway:\n  errorInterceptor:\n    enabled: true\n", "errorInterceptor middleware"},
		{"gateway cors", "gateway:\n  cors:\n    origins: []\n", "responseHeaders middleware"},
		{"gateway tls keys", "gateway:\n  tls:\n    keys:\n      - cert: a\n        key: b\n", "use `certificates`"},

		{"route destination", routeConfig("destination: http://api:8080"), "use `target`"},
		{"route disabled", routeConfig("disabled: true"), "use `enabled`"},
		{"route blockCommonExploits", routeConfig("blockCommonExploits: true"), "security.enableExploitProtection"},
		{"route disableHostForwarding", routeConfig("disableHostForwarding: true"), "security.forwardHostHeaders"},
		{"route insecureSkipVerify", routeConfig("insecureSkipVerify: true"), "security.tls.insecureSkipVerify"},
		{"route cors", routeConfig("cors:\n        origins: []"), "responseHeaders middleware"},
		{"route errorInterceptor", routeConfig("errorInterceptor:\n        enabled: true"), "errorInterceptor middleware"},
		{"route security.tls.SkipVerification",
			routeConfig("security:\n        tls:\n          SkipVerification: true"), "use `insecureSkipVerify`"},

		{"jwt alg", middlewareConfig("jwt", "alg: HS256"), "use `algorithms`"},
		{"jwt forwardHeaders", middlewareConfig("jwt", "forwardHeaders:\n        X-User: sub"), "use `forward.headers`"},
		{"jwtAuth alg", middlewareConfig("jwtAuth", "alg: HS256"), "use `algorithms`"},
		{"forwardAuth enableHostForwarding",
			middlewareConfig("forwardAuth", "enableHostForwarding: true"), "use `forwardHostHeaders`"},
		{"forwardAuth skipInsecureVerify",
			middlewareConfig("forwardAuth", "skipInsecureVerify: true"), "use `insecureSkipVerify`"},
		{"oidc redirectUrl", middlewareConfig("oidc", "redirectUrl: https://e.com/cb"), "use `callbackPath`"},
		{"oidc redirectPath", middlewareConfig("oidc", "redirectPath: /home"), "use `postLoginRedirect`"},
		{"oidc cookiePath", middlewareConfig("oidc", "cookiePath: /"), "use `session.cookie.path`"},
		{"oidc state", middlewareConfig("oidc", "state: fixed"), "random per login"},
		{"middleware type oauth", middlewareConfig("oauth", "clientId: x"), "use type: oidc"},
		{"middleware type oauth2", middlewareConfig("oauth2", "clientId: x"), "use type: oidc"},
		{"errorInterceptor code",
			middlewareConfig("errorInterceptor", "errors:\n        - code: 404\n          body: nope"), "use `statusCode`"},
		{"errorInterceptor status",
			middlewareConfig("errorInterceptor", "errors:\n        - status: 404\n          body: nope"), "use `statusCode`"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := checkRemovedKeys("test config", []byte(tc.config))
			if err == nil {
				t.Fatalf("checkRemovedKeys() = nil, want the removed key rejected\nconfig:\n%s", tc.config)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("checkRemovedKeys() = %q, want it to mention %q", err, tc.want)
			}
		})
	}
}

// A configuration that uses only supported keys must load unchanged.
func TestCheckRemovedKeysAcceptsCurrentConfig(t *testing.T) {
	config := `
version: "2"
certManager:
  acme:
    email: admin@example.com
gateway:
  timeouts:
    read: 30
    write: 30
    idle: 60
  monitoring:
    enableMetrics: true
  tls:
    certificates:
      - cert: /a.crt
        key: /a.key
  routes:
    - name: api
      path: /api
      target: http://api:8080
      enabled: false
      security:
        enableExploitProtection: true
        forwardHostHeaders: false
        tls:
          insecureSkipVerify: true
      middlewares: [sso, headers]
middlewares:
  - name: sso
    type: oidc
    rule:
      clientId: goma
      clientSecret: secret
      callbackPath: /callback
      postLoginRedirect: /dashboard
      session:
        cookie:
          path: /
  - name: auth
    type: jwt
    rule:
      secret: s
      algorithms: ["HS256"]
      forward:
        headers:
          X-User: sub
  - name: headers
    type: responseHeaders
    rule:
      cors:
        enabled: true
        origins: ["https://example.com"]
  - name: errors
    type: errorInterceptor
    rule:
      enabled: true
      errors:
        - statusCode: 404
          body: "not found"
`
	if err := checkRemovedKeys("test config", []byte(config)); err != nil {
		t.Fatalf("checkRemovedKeys() = %v, want nil for a v1.0 configuration", err)
	}
}

// A key that is still valid on one middleware must not be reported because it
// was removed from another: forwardAuth and ldap both keep insecureSkipVerify.
func TestCheckRemovedKeysIsScopedToMiddlewareType(t *testing.T) {
	config := middlewareConfig("forwardAuth", "insecureSkipVerify: true")
	if err := checkRemovedKeys("test config", []byte(config)); err != nil {
		t.Fatalf("checkRemovedKeys() = %v, want nil: insecureSkipVerify is still valid on forwardAuth", err)
	}
}

// Extra-config files hold a bare routes: or middlewares: list, with no gateway
// block above them, and are checked the same way.
func TestCheckRemovedKeysScansExtraConfigFiles(t *testing.T) {
	routes := "routes:\n  - name: api\n    path: /api\n    destination: http://api:8080\n"
	err := checkRemovedKeys("extra routes", []byte(routes))
	if err == nil || !strings.Contains(err.Error(), "use `target`") {
		t.Fatalf("checkRemovedKeys(extra routes) = %v, want destination rejected", err)
	}

	mids := "middlewares:\n  - name: sso\n    type: oauth\n    rule:\n      clientId: x\n"
	err = checkRemovedKeys("extra middlewares", []byte(mids))
	if err == nil || !strings.Contains(err.Error(), "use type: oidc") {
		t.Fatalf("checkRemovedKeys(extra middlewares) = %v, want type: oauth rejected", err)
	}
}

// The report names the route and the line, so a large configuration does not
// have to be searched by hand, and lists every key in one pass.
func TestCheckRemovedKeysReportsLocationAndListsAll(t *testing.T) {
	config := `gateway:
  readTimeout: 30
  routes:
    - name: checkout
      path: /checkout
      destination: http://checkout:8080
      disabled: true
`
	err := checkRemovedKeys("test config", []byte(config))
	if err == nil {
		t.Fatal("checkRemovedKeys() = nil, want an error")
	}
	message := err.Error()
	for _, want := range []string{"line 2", "line 6", "line 7", "gateway.routes[0] (checkout)", "readTimeout", "destination", "disabled"} {
		if !strings.Contains(message, want) {
			t.Errorf("checkRemovedKeys() = %q, want it to contain %q", message, want)
		}
	}
}

// A syntax error belongs to the real decoder, which reports it with position
// and context; the removed-key scan stays quiet rather than masking it.
func TestCheckRemovedKeysIgnoresUnparseableConfig(t *testing.T) {
	if err := checkRemovedKeys("test config", []byte("gateway:\n\tbad: [unclosed\n")); err != nil {
		t.Errorf("checkRemovedKeys(invalid yaml) = %v, want nil so the parser reports it", err)
	}
}

// routeConfig wraps route keys in a minimal gateway document.
func routeConfig(keys string) string {
	return "gateway:\n  routes:\n    - name: api\n      path: /api\n      target: http://api:8080\n      " + keys + "\n"
}

// middlewareConfig wraps rule keys in a minimal middleware document.
func middlewareConfig(middlewareType, rule string) string {
	return "middlewares:\n  - name: mw\n    type: " + middlewareType + "\n    rule:\n      " + rule + "\n"
}
