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
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// loadExtraFiles loads routes files in .yml and .yaml based on defined directory
func loadExtraFiles(routePath string) ([]string, error) {
	// Slice to store YAML/YML files
	var yamlFiles []string
	// Walk through the Directory
	err := filepath.Walk(routePath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		// Skip hidden folders
		if info.IsDir() && info.Name()[0] == '.' {
			return filepath.SkipDir
		}
		// Check for .yaml or .yml file extension
		if !info.IsDir() && (filepath.Ext(path) == ".yaml" || filepath.Ext(path) == ".yml") {
			yamlFiles = append(yamlFiles, path)
		}
		return nil
	})

	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			logger.Error("Error,", "error", err)
			return yamlFiles, nil
		}
		return nil, fmt.Errorf("error loading extra config files: %v", err)
	}
	return yamlFiles, nil
}
