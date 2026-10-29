package internal

import "testing"

func TestRedirectHostRuleValidate(t *testing.T) {
	for _, c := range []struct {
		name string
		rule RedirectHostRuleMiddleware
		ok   bool
	}{
		{"add www", RedirectHostRuleMiddleware{WWW: "add"}, true},
		{"remove www", RedirectHostRuleMiddleware{WWW: "remove"}, true},
		{"fixed host", RedirectHostRuleMiddleware{Host: "example.com"}, true},
		{"fixed host with port", RedirectHostRuleMiddleware{Host: "example.com:8443"}, true},
		{"empty", RedirectHostRuleMiddleware{}, false},
		{"both", RedirectHostRuleMiddleware{WWW: "add", Host: "example.com"}, false},
		{"bad www", RedirectHostRuleMiddleware{WWW: "strip"}, false},
		{"url instead of host", RedirectHostRuleMiddleware{Host: "https://example.com/"}, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			if err := c.rule.validate(); (err == nil) != c.ok {
				t.Fatalf("validate() = %v, want ok=%v", err, c.ok)
			}
		})
	}
}
