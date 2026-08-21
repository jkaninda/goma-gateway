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

import "testing"

// The documented examples all use single quotes, so they have to parse and
// evaluate. Backticks stay supported for configurations written against the
// original implementation.
func TestClaimsExpressionQuoteStyles(t *testing.T) {
	claims := map[string]interface{}{
		"email":            "admin@example.com",
		claimEmailVerified: true,
		"roles":            []interface{}{"admin", "auditor"},
		"plan":             "pro",
		"profile":          map[string]interface{}{"department": "engineering"},
	}

	tests := []struct {
		expression string
		want       bool
	}{
		{"Equals('email_verified', true)", true},
		{`Equals("email_verified", true)`, true},
		{"Equals(`email_verified`, `true`)", true},
		{"Equals('plan', 'free')", false},
		{"Prefix('email', 'admin@')", true},
		{"Contains('roles', 'admin')", true},
		{"Contains('roles', 'intern')", false},
		{"OneOf('plan', 'pro', 'enterprise')", true},
		{"OneOf('plan', 'free', 'trial')", false},
		{"Equals('profile.department', 'engineering')", true},
		{"Equals('email_verified', true) && OneOf('plan', 'pro', 'enterprise')", true},
		{"!Equals('plan', 'free') && Contains('roles', 'admin')", true},
		{"Equals('plan', 'free') || Contains('roles', 'auditor')", true},
	}

	for _, test := range tests {
		t.Run(test.expression, func(t *testing.T) {
			expression, err := ParseExpression(test.expression)
			if err != nil {
				t.Fatalf("ParseExpression(%q) = %v, want nil", test.expression, err)
			}
			got, err := expression.Evaluate(claims)
			if err != nil {
				t.Fatalf("Evaluate() = %v, want nil", err)
			}
			if got != test.want {
				t.Errorf("Evaluate(%q) = %v, want %v", test.expression, got, test.want)
			}
		})
	}
}
