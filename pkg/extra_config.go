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

package pkg

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// loadExtraFiles loads route files in .yml and .yaml format from the specified directory
func loadExtraFiles(path string) ([]string, error) {
	var yamlFiles []string

	err := filepath.Walk(path, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip hidden directories
		if info.IsDir() && strings.HasPrefix(info.Name(), ".") {
			return filepath.SkipDir
		}

		// Include .yaml or .yml files
		if !info.IsDir() && (filepath.Ext(path) == ".yaml" || filepath.Ext(path) == ".yml") {
			yamlFiles = append(yamlFiles, path)
		}

		return nil
	})

	if err != nil {
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, os.ErrPermission) {
			logger.Error("Error accessing directory", "path", path, "error", err)
			return nil, nil
		}
		return nil, fmt.Errorf("error walking through directory %s: %w", path, err)
	}
	return yamlFiles, nil
}
