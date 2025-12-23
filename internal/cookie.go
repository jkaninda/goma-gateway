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

// Cookie defines a cookie to set in the response
type Cookie struct {
	Name  string           `yaml:"name"`
	Value string           `yaml:"value"`
	Attrs CookieAttributes `yaml:"attributes,omitempty"`
}

// CookieAttributes defines cookie attributes (flags and metadata)
type CookieAttributes struct {
	Path     string `yaml:"path,omitempty"`
	Domain   string `yaml:"domain,omitempty"`
	MaxAge   int    `yaml:"maxAge,omitempty"` // 0 = session, -1 = delete, >0 = persistent
	Secure   bool   `yaml:"secure,omitempty"`
	HttpOnly bool   `yaml:"httpOnly,omitempty"`
	SameSite string `yaml:"sameSite,omitempty"` // Strict, Lax, None
}
