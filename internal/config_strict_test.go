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
	"os"
	"path/filepath"
	"strings"
	"testing"

	goutils "github.com/jkaninda/go-utils"
)

const strictTestConfig = `version: 2
gateway:
  routes:
    - name: api
      path: /
      target: http://localhost:8080
      bogusKey: 1
      tls:
        certificates:
          - cert: a
middlewares:
  - name: limit
    type: rateLimit
    rule:
      unit: minute
      requestsPerUnit: 10
      notAField: 3
      otherTypo: 4
  - name: jwt
    type: jwtAuth
    rule:
      jwksUrl: https://sso.example.com/jwks
      audience: api
`

func TestUnknownKeys(t *testing.T) {
	got := strings.Join(unknownKeys([]byte(strictTestConfig), &GatewayConfig{}), "\n")
	for _, want := range []string{
		`line 7: unknown key "bogusKey"`,
		`line 9: unknown key "certificates"`,
		`rule field "notAField" is not a rateLimit option`,
		`rule field "otherTypo" is not a rateLimit option`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
}

func TestUnknownKeysAcceptsValidConfig(t *testing.T) {
	valid := `version: 2
gateway:
  tls:
    clientAuth:
      clientCA: /etc/goma/ca.pem
  routes:
    - name: api
      path: /
      hosts: [api.example.com]
      tls:
        provider: none
        certificate:
          cert: /etc/goma/api.crt
          key: /etc/goma/api.key
      backends:
        - endpoint: http://v1:8080
          weight: 90
        - endpoint: http://v2:8080
          weight: 10
          match:
            - source: header
              name: X-Beta
              operator: equals
              value: "true"
      security:
        enableExploitProtection: true
      middlewares: [headers]
middlewares:
  - name: headers
    type: responseHeaders
    rule:
      setCookies:
        - name: session
          value: x
          attributes:
            httpOnly: true
            sameSite: Strict
certManager:
  providers:
    letsencrypt:
      type: acme
      acme:
        email: ops@example.com
`
	if got := unknownKeys([]byte(valid), &GatewayConfig{}); len(got) != 0 {
		t.Fatalf("valid configuration reported unknown keys:\n%s", strings.Join(got, "\n"))
	}
}

func TestCheckConfigReportsProblems(t *testing.T) {
	path := filepath.Join(t.TempDir(), "goma.yml")
	if err := os.WriteFile(path, []byte(strictTestConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	err := CheckConfig(path)
	if err == nil {
		t.Fatal("expected config check to fail")
	}
	for _, want := range []string{`unknown key "bogusKey"`, `middleware "jwt" (jwtAuth): empty issuer`} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("missing %q in:\n%v", want, err)
		}
	}
}

func TestCookieAttributesAreDecoded(t *testing.T) {
	rule := &ResponseHeader{}
	err := goutils.DeepCopy(rule, map[string]any{
		"setCookies": []any{map[string]any{
			"name": "session", "value": "x",
			"attributes": map[string]any{"httpOnly": true, "secure": true, "sameSite": "Strict"},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	a := rule.SetCookies[0].Attrs
	if !a.HttpOnly || !a.Secure || a.SameSite != "Strict" {
		t.Fatalf("cookie attributes were not decoded: %+v", a)
	}
}
