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

package error_interceptor

type ErrorInterceptor struct {
	// ContentType error response content type, application/json, plain/text
	ContentType string `yaml:"contentType"`
	//Errors contains error status code and custom message
	Errors []Error `yaml:"errors"`
}
type Error struct {
	// Code HTTP status code
	Code int `yaml:"code"`
	// Message custom message
	Message string `yaml:"message"`
}
