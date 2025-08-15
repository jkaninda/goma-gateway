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
	"context"
	"github.com/go-redis/redis_rate/v10"
	"github.com/jkaninda/goma-gateway/util"
	"github.com/redis/go-redis/v9"
)

type Redis struct {
	// Addr redis hostname and port number :
	Addr           string `yaml:"addr"`
	Password       string `yaml:"password"`
	DB             int    `yaml:"db"`             // Redis database number (0–15)
	FlushOnStartup bool   `yaml:"flushOnStartup"` // FlushOnStartup indicates whether to flush the Redis database on startup

}

func (r *Redis) InitRedis() {
	RedisClient = redis.NewClient(&redis.Options{
		Addr:     util.ReplaceEnvVars(r.Addr),
		Password: util.ReplaceEnvVars(r.Password),
		DB:       r.DB,
	})
	limiter = redis_rate.NewLimiter(RedisClient)
	if r.FlushOnStartup {
		if err := RedisClient.FlushDBAsync(context.Background()).Err(); err != nil {
			logger.Error("Error flushing Redis database", "error", err)
		} else {
			logger.Info("Redis database flushed successfully")
		}
	}
}
