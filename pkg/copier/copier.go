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

package copier

import (
	"encoding/json"
	"fmt"
	"reflect"
)

// Copy converts an interface{} to a target struct
func Copy(input interface{}, output interface{}) error {
	// Ensure output is a pointer to a struct
	val := reflect.ValueOf(output)
	if val.Kind() != reflect.Ptr || val.Elem().Kind() != reflect.Struct {
		return fmt.Errorf("output must be a pointer to a struct")
	}

	// Marshal the input to JSON, then unmarshal into the output
	data, err := json.Marshal(input)
	if err != nil {
		return fmt.Errorf("failed to marshal input: %v", err)
	}

	err = json.Unmarshal(data, output)
	if err != nil {
		return fmt.Errorf("failed to unmarshal to output struct: %v", err)
	}

	return nil
}
