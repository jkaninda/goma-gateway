package middlewares

import (
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func TestContainsIsMembershipNotSubstring(t *testing.T) {
	cases := []struct {
		name   string
		claims jwt.MapClaims
		want   bool
	}{
		{"exact array element", jwt.MapClaims{"roles": []interface{}{"admin"}}, true},
		{"superadmin must not pass", jwt.MapClaims{"roles": []interface{}{"superadmin"}}, false},
		{"not-admin must not pass", jwt.MapClaims{"roles": []interface{}{"not-admin"}}, false},
		{"space separated string", jwt.MapClaims{"roles": "user admin"}, true},
		{"substring in string must not pass", jwt.MapClaims{"roles": "superadmin"}, false},
		{"comma separated string", jwt.MapClaims{"roles": "user,admin"}, true},
	}
	for _, c := range cases {
		got, err := Contains("roles", "admin").Evaluate(c.claims)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}

func TestParseExpressionRejectsTrailingInput(t *testing.T) {
	// A missing "&&" must be an error, not a silently truncated policy.
	if _, err := ParseExpression("Contains('roles','admin') Equals('plan','pro')"); err == nil {
		t.Fatal("expected an error for trailing input")
	}
	if _, err := ParseExpression("Contains('roles','admin') && Equals('plan','pro')"); err != nil {
		t.Fatalf("valid expression rejected: %v", err)
	}
}
