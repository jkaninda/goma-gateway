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
	"fmt"
	"testing"
)

func TestValidateMD5Crypt(t *testing.T) {
	password := "password123"
	hash := "$1$salt$qJH7.N4xYta3aEG/dfqo/0"

	isValid, err := validateMD5Crypt(password, hash)
	if err != nil {
		t.Errorf("Error: %v\n", err)
		return
	}

	fmt.Printf("Password: %s\n", password)
	fmt.Printf("Hash: %s\n", hash)
	fmt.Printf("Valid: %t\n", isValid)

	// Generate a new hash for comparison
	newHash := generateMD5Crypt(password, "salt")

	fmt.Printf("Generated hash: %s\n", newHash)
}

// Path fixtures shared by the package's tests.
const (
	testAllPaths      = "/.*"
	testAdminWildcard = "/admin/*"
)

// A pattern that is not a regular expression must not stop the ones beside it
// from being matched, and it still matches as a wildcard.
func TestPathMatchingMixesWildcardsAndRegex(t *testing.T) {
	paths := []string{"/legacy/*", "/api/v[0-9]+/.*"}

	tests := []struct {
		path string
		want bool
	}{
		{"/api/v2/users", true},   // regex, listed after the invalid pattern
		{"/api/v10/users", true},  // regex again
		{"/legacy/reports", true}, // wildcard fallback
		{"/legacy", true},         // wildcard fallback, base path
		{"/public", false},
	}

	for _, test := range tests {
		t.Run(test.path, func(t *testing.T) {
			if got := isPathMatching(test.path, "/", paths); got != test.want {
				t.Errorf("isPathMatching(%q, %v) = %v, want %v", test.path, paths, got, test.want)
			}
		})
	}
}

func TestRegexHint(t *testing.T) {
	tests := map[string]string{
		"/*":              testAllPaths,
		testAdminWildcard: "/admin/.*",
		"/tenant/*/api/*": "/tenant/.*/api/.*",
		"/already/.*":     "/already/.*",
		"/exact":          "/exact",
	}
	for pattern, want := range tests {
		if got := regexHint(pattern); got != want {
			t.Errorf("regexHint(%q) = %q, want %q", pattern, got, want)
		}
	}
}

// An unusable pattern is compiled once and reported once, not on every request.
func TestPatternCompilationIsCached(t *testing.T) {
	pattern := "/uncacheable-[test/*"
	compiledPatterns.Delete(pattern)

	first := compilePattern(pattern)
	second := compilePattern(pattern)

	if first != second {
		t.Error("compilePattern returned a new entry for a pattern it had already seen")
	}
	if first.err == nil {
		t.Error("compilePattern reported an invalid pattern as valid")
	}
}
