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
	"crypto/md5"
	"fmt"
	logger2 "github.com/jkaninda/logger"
)

// generateMD5Crypt implements the MD5 crypt algorithm
func generateMD5Crypt(password, salt string) string {
	// Limit salt to 8 characters max
	if len(salt) > 8 {
		salt = salt[:8]
	}

	// Step 1: Create initial digest
	h1 := md5.New()
	h1.Write([]byte(password))
	h1.Write([]byte("$1$"))
	h1.Write([]byte(salt))

	// Step 2: Create alternate digest
	h2 := md5.New()
	h2.Write([]byte(password))
	h2.Write([]byte(salt))
	h2.Write([]byte(password))
	alt := h2.Sum(nil)

	// Step 3: Add alternate digest to initial digest
	for i := len(password); i > 0; i -= 16 {
		if i > 16 {
			h1.Write(alt)
		} else {
			h1.Write(alt[:i])
		}
	}

	// Step 4: Handle password length bits
	for i := len(password); i > 0; i >>= 1 {
		if i&1 == 1 {
			h1.Write([]byte{0})
		} else {
			h1.Write([]byte{password[0]})
		}
	}

	digest := h1.Sum(nil)

	// Step 5: Perform 1000 iterations
	for i := 0; i < 1000; i++ {
		h := md5.New()

		if i&1 == 1 {
			h.Write([]byte(password))
		} else {
			h.Write(digest)
		}

		if i%3 != 0 {
			h.Write([]byte(salt))
		}

		if i%7 != 0 {
			h.Write([]byte(password))
		}

		if i&1 == 1 {
			h.Write(digest)
		} else {
			h.Write([]byte(password))
		}

		digest = h.Sum(nil)
	}

	// Step 6: Create the final hash string using custom base64-like encoding
	encoded := encodeMD5Hash(digest)

	return fmt.Sprintf("$1$%s$%s", salt, encoded)
}

// encodeMD5Hash encodes the MD5 digest using the custom MD5 crypt alphabet
func encodeMD5Hash(digest []byte) string {
	alphabet := "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

	result := make([]byte, 0, 22)

	// MD5 crypt uses a specific byte reordering and grouping
	// Process in groups of 3 bytes with specific ordering
	groups := [][3]int{
		{0, 6, 12},
		{1, 7, 13},
		{2, 8, 14},
		{3, 9, 15},
		{4, 10, 5},
		{11, -1, -1}, // Last group has only 1 byte
	}

	for i, group := range groups {
		var val int
		var chars int

		if i == 5 { // Last group (only 1 byte)
			val = int(digest[group[0]])
			chars = 2
		} else {
			val = int(digest[group[0]]) | (int(digest[group[1]]) << 8) | (int(digest[group[2]]) << 16)
			chars = 4
		}

		for j := 0; j < chars; j++ {
			result = append(result, alphabet[val&0x3f])
			val >>= 6
		}
	}

	return string(result)
}
func InitLogger(l *logger2.Logger) {
	logger = l
}
