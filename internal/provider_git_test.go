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
	"context"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
	"time"
)

func TestGitProvider_PublicRepo(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	stopCh := make(chan struct{})
	defer close(stopCh)

	cfg := &GitProvider{
		Enabled:  true,
		URL:      "https://github.com/jkaninda/goma-gateway-production-deployment.git",
		Path:     "gateway/extra",
		Branch:   "main",
		Interval: 60 * time.Second,
		CloneDir: "tests/git-provider",
	}

	// Clean up
	defer func(path string) {
		err := os.RemoveAll(path)
		if err != nil {
			t.Error("Error", err)
		}
	}(cfg.CloneDir)

	provider, err := NewGitProvider(cfg)
	assert.NoError(t, err)

	ctx := context.Background()
	bundle, err := provider.Load(ctx)

	logger.Info("Config loaded", "routes count", len(bundle.Routes), "middlewares count", len(bundle.Middlewares))
	assert.NoError(t, err)
	assert.NotNil(t, bundle)
	assert.NotEmpty(t, bundle.Version)
}
