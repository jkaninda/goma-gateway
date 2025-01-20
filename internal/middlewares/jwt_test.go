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
	"log"
	"testing"
)

func TestCreateJWT(t *testing.T) {
	jwtSecret := "MgsEUFgn9xiMym9Lo9rcRUa3wJbQBo"
	jwtToken, err := CreateJWT("user@example.com", jwtSecret)
	if err != nil {
		t.Fatalf("Error creating JWT token")
	}
	log.Println(jwtToken)
	ok, err := validateJWT(jwtToken, jwtSecret)
	if err != nil {
		t.Fatalf("Erro validating JWT token")
	}
	if ok {
		log.Println("Validated")
	}
}
