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
	"github.com/golang-jwt/jwt"
	"time"
)

// CreateJWT create JWT token
func CreateJWT(email, jwtSecret string) (string, error) {
	// Define JWT claims
	claims := jwt.MapClaims{
		"email": email,
		"exp":   jwt.TimeFunc().Add(time.Hour * 6).Unix(), // Token expiration
		"iss":   "Goma",                                   // Issuer claim
	}

	// Create a new token with HS256 signing method
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Sign the token with a secret
	signedToken, err := token.SignedString([]byte(jwtSecret))
	if err != nil {
		return "", err
	}

	return signedToken, nil
}
func validateJWT(signedToken, jWTSecret string) (bool, error) {
	// Parse the JWT token and provide the key function
	token, err := jwt.Parse(signedToken, func(token *jwt.Token) (interface{}, error) {
		// Ensure the signing method is HMAC and specifically HS256
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		// Return the shared secret key for validation
		return []byte(jWTSecret), nil
	})

	// If there's an error or token is invalid, return false
	if err != nil || !token.Valid {
		return false, fmt.Errorf("token is invalid: %v", err)
	}

	// Check if token claims are valid
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		// Optional: Check token expiration
		if exp, ok := claims["exp"].(float64); ok {
			if time.Unix(int64(exp), 0).Before(time.Now()) {
				return false, fmt.Errorf("token has expired")
			}
		}

		// Token is valid and not expired
		return true, nil
	}

	return false, fmt.Errorf("token is invalid or missing claims")
}
