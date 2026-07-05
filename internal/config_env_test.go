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
	"testing"

	"gopkg.in/yaml.v3"
)

// TestReadConfigFileExpandsEnv verifies that declarative config files have
// ${VAR} references resolved from the environment at load time, while values
// that merely contain a bare `$` (e.g. bcrypt hashes) and references to unset
// variables are left untouched.
func TestReadConfigFileExpandsEnv(t *testing.T) {
	t.Setenv("TEST_HOST", "api.example.com")
	t.Setenv("TEST_REDIS_PASSWORD", "s3cr3t")
	t.Setenv("TEST_ACME_EMAIL", "ops@example.com")

	const bcrypt = "$2y$05$TIx7l8sJWvMFXw4n0GbkQuOhemPQOormacQC4W1p28TOVzJtx.XpO"
	raw := "" +
		"host: ${TEST_HOST}\n" +
		"password: ${TEST_REDIS_PASSWORD}\n" +
		"email: ${TEST_ACME_EMAIL}\n" +
		"bcrypt: \"" + bcrypt + "\"\n" +
		"unset: ${TEST_DOES_NOT_EXIST}\n"

	path := filepath.Join(t.TempDir(), "goma.yml")
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write temp config: %v", err)
	}

	buf, err := readConfigFile(path)
	if err != nil {
		t.Fatalf("readConfigFile: %v", err)
	}

	var got struct {
		Host     string `yaml:"host"`
		Password string `yaml:"password"`
		Email    string `yaml:"email"`
		Bcrypt   string `yaml:"bcrypt"`
		Unset    string `yaml:"unset"`
	}
	if err := yaml.Unmarshal(buf, &got); err != nil {
		t.Fatalf("unmarshal expanded config: %v", err)
	}

	if got.Host != "api.example.com" {
		t.Errorf("host: want %q, got %q", "api.example.com", got.Host)
	}
	if got.Password != "s3cr3t" {
		t.Errorf("password: want %q, got %q", "s3cr3t", got.Password)
	}
	if got.Email != "ops@example.com" {
		t.Errorf("email: want %q, got %q", "ops@example.com", got.Email)
	}
	// A bare `$` (no braces) must never be treated as a variable reference.
	if got.Bcrypt != bcrypt {
		t.Errorf("bcrypt hash was mangled: want %q, got %q", bcrypt, got.Bcrypt)
	}
	// Unset variables are preserved verbatim rather than blanked.
	if got.Unset != "${TEST_DOES_NOT_EXIST}" {
		t.Errorf("unset var: want %q preserved, got %q", "${TEST_DOES_NOT_EXIST}", got.Unset)
	}
}
