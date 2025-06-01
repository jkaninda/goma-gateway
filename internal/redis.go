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
	"github.com/jkaninda/goma-gateway/internal/middlewares"
)

func (gatewayServer GatewayServer) initRedis() {
	if len(gatewayServer.gateway.Redis.Addr) != 0 {
		logger.Info("Initializing Redis...")
		middlewares.InitRedis(gatewayServer.gateway.Redis.Addr, gatewayServer.gateway.Redis.Password)
	}

}

func (gatewayServer GatewayServer) closeRedis() {
	if middlewares.RedisClient != nil {
		if err := middlewares.RedisClient.Close(); err != nil {
			logger.Error("Error closing Redis", "error", err)
		}
	}
}
