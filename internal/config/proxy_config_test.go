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

package config

import (
	"reflect"
	"testing"
)

func TestApplyEnvOverridesFile(t *testing.T) {
	t.Setenv(ProxyEnabledEnv, "true")
	t.Setenv(ProxyTrustedProxiesEnv, " 173.245.48.0/20, 2400:cb00::/32 ,,")
	t.Setenv(ProxyIPHeadersEnv, "CF-Connecting-IP,X-Forwarded-For")

	p := ProxyConfig{TrustedProxies: []string{"10.0.0.0/8"}, IPHeaders: []string{"X-Real-IP"}}
	p.ApplyEnv()

	if !p.Enabled {
		t.Error("GOMA_PROXY_ENABLED=true did not enable proxy mode")
	}
	if want := []string{"173.245.48.0/20", "2400:cb00::/32"}; !reflect.DeepEqual(p.TrustedProxies, want) {
		t.Errorf("TrustedProxies = %q, want %q", p.TrustedProxies, want)
	}
	if want := []string{"CF-Connecting-IP", "X-Forwarded-For"}; !reflect.DeepEqual(p.IPHeaders, want) {
		t.Errorf("IPHeaders = %q, want %q", p.IPHeaders, want)
	}
	if _, err := p.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if !p.IsTrustedSource("173.245.48.10") || p.IsTrustedSource("10.1.2.3") {
		t.Error("trusted sources should come from the environment, not the file")
	}
}

func TestApplyEnvLeavesFileWhenUnset(t *testing.T) {
	t.Setenv(ProxyTrustedProxiesEnv, "")
	t.Setenv(ProxyIPHeadersEnv, " , ")

	p := ProxyConfig{Enabled: true, TrustedProxies: []string{"10.0.0.0/8"}, IPHeaders: []string{"X-Real-IP"}}
	p.ApplyEnv()

	if !p.Enabled {
		t.Error("an unset GOMA_PROXY_ENABLED must keep the file's value")
	}
	if !reflect.DeepEqual(p.TrustedProxies, []string{"10.0.0.0/8"}) || !reflect.DeepEqual(p.IPHeaders, []string{"X-Real-IP"}) {
		t.Errorf("empty variables must not replace the file's lists: got %q / %q", p.TrustedProxies, p.IPHeaders)
	}
}

func TestApplyEnvCanDisable(t *testing.T) {
	t.Setenv(ProxyEnabledEnv, "false")
	p := ProxyConfig{Enabled: true, TrustedProxies: []string{"10.0.0.0/8"}}
	p.ApplyEnv()
	if p.Enabled {
		t.Error("GOMA_PROXY_ENABLED=false must turn off proxy mode set in the file")
	}
}
