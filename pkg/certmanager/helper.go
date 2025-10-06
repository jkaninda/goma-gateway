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

package certmanager

import (
	"fmt"
	"github.com/jkaninda/logger"
	"os"
	"path/filepath"
)

func initializeStorageConfig(storageFile string) (*StorageConfig, error) {
	if storageFile == "" {
		return &StorageConfig{CacheDir: cacheDir, StorageFile: filepath.Join(cacheDir, acmeFile)}, nil
	}

	file := filepath.Base(storageFile)
	if file == "" {
		file = acmeFile
	}
	// Check if storage file already exists
	if _, err := os.Stat(storageFile); err == nil {
		return &StorageConfig{
			CacheDir:    filepath.Dir(storageFile),
			StorageFile: storageFile,
		}, nil
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("failed to check storage file: %w", err)
	}

	// File doesn't exist, create directory structure
	baseDir := filepath.Dir(storageFile)
	if baseDir == "" || baseDir == "." {
		return &StorageConfig{
			CacheDir:    cacheDir,
			StorageFile: filepath.Join(cacheDir, file),
		}, nil
	}

	if err := os.MkdirAll(baseDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create directory %s: %w", baseDir, err)
	}

	logger.Debug("Created certificate storage directory", "path", baseDir)
	return &StorageConfig{
		CacheDir:    baseDir,
		StorageFile: filepath.Join(baseDir, file),
	}, nil
}
