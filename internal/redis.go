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
	"github.com/jkaninda/goma-gateway/pkg/middlewares"
)

func (g *GatewayServer) initRedis() {
	if g.gateway.Redis.Addr == "" {
		return
	}

	logger.Info("Initializing Redis...")

	if err := g.gateway.Redis.InitRedis(); err != nil {
		logger.Error("Redis initialization failed", "error", err)
		logger.Warn("Falling back to in-memory rate limiting and caching")
		return
	}

	redisBased = true
	logger.Info("Redis successfully initialized")
}

func (g *GatewayServer) closeRedis() {
	if middlewares.RedisClient != nil {
		if err := middlewares.RedisClient.Close(); err != nil {
			logger.Error("Error closing Redis", "error", err)
		}
	}
}
