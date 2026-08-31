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

// generateMD5Crypt implements the MD5 crypt algorithm with the classic "$1$"
// magic. Apache's htpasswd variant is the same algorithm under a different
// magic string; see generateMD5CryptWithMagic.
func generateMD5Crypt(password, salt string) string {
	return generateMD5CryptWithMagic(password, salt, "$1$")
}

func generateMD5CryptWithMagic(password, salt, magic string) string {
	// Limit salt to 8 characters max
	if len(salt) > 8 {
		salt = salt[:8]
	}

	// Step 1: Create initial digest
	h1 := md5.New()
	h1.Write([]byte(password))
	h1.Write([]byte(magic))
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

	return fmt.Sprintf("%s%s$%s", magic, salt, encoded)
}

// md5CryptAlphabet is the base64-like alphabet MD5 crypt encodes with. Note the
// leading "./" — it is not standard base64.
const md5CryptAlphabet = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// md5CryptGroups is the byte reordering MD5 crypt applies to the digest: five
// groups of three, each emitted as four characters, little-endian.
var md5CryptGroups = [5][3]int{
	{0, 6, 12},
	{1, 7, 13},
	{2, 8, 14},
	{3, 9, 15},
	{4, 10, 5},
}

// encodeMD5Hash encodes the MD5 digest using the custom MD5 crypt alphabet.
func encodeMD5Hash(digest []byte) string {
	if len(digest) < md5.Size {
		return ""
	}

	result := make([]byte, 0, 22)
	emit := func(value, chars int) {
		for range chars {
			result = append(result, md5CryptAlphabet[value&0x3f])
			value >>= 6
		}
	}

	for _, group := range md5CryptGroups {
		emit(int(digest[group[0]])<<16|int(digest[group[1]])<<8|int(digest[group[2]]), 4)
	}
	// The sixteenth byte is left over and encodes to two characters.
	emit(int(digest[11]), 2)

	return string(result)
}
func InitLogger(l *logger2.Logger) {
	logger = l
}
