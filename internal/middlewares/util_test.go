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
