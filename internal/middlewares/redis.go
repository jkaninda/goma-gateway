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
	"crypto/tls"
	"fmt"
	"github.com/go-redis/redis_rate/v10"
	goutils "github.com/jkaninda/go-utils"
	"github.com/redis/go-redis/v9"
)

type Redis struct {
	// Addr redis hostname and port number :
	Addr           string `yaml:"addr"`
	Password       string `yaml:"password"`
	DB             int    `yaml:"db"`             // Redis database number (0–15)
	FlushOnStartup bool   `yaml:"flushOnStartup"` // FlushOnStartup indicates whether to flush the Redis database on startup
	// TLS contains optional TLS configuration settings for Redis.
	TLS RedisTLS `yaml:"tls,omitempty"`
}

// RedisTLS defines the TLS configuration for Redis connections.
type RedisTLS struct {
	ClientCA   string `yaml:"clientCa,omitempty"`
	ClientCert string `yaml:"clientCert,omitempty"`
	ClientKey  string `yaml:"clientKey,omitempty"`
}

func (r *Redis) InitRedis() error {
	ctx := context.Background()
	var (
		tlsConfig *tls.Config
		err       error
	)

	// Prepare TLS config if provided
	if r.TLS.ClientCA != "" && r.TLS.ClientCert != "" && r.TLS.ClientKey != "" {
		tlsConfig, err = goutils.LoadTLSConfig(r.TLS.ClientCert, r.TLS.ClientKey, r.TLS.ClientCA, true)
		if err != nil {
			logger.Error("Failed to load Redis TLS configuration", "error", err)
			return fmt.Errorf("failed to load Redis TLS config: %w", err)
		}
		logger.Debug("Redis TLS configuration applied")
	}
	// Create Redis client
	RedisClient = redis.NewClient(&redis.Options{
		Addr:      goutils.Env("GOMA_REDIS_ADDR", goutils.ReplaceEnvVars(r.Addr)),
		Password:  goutils.Env("GOMA_REDIS_PASSWORD", goutils.ReplaceEnvVars(r.Password)),
		DB:        goutils.EnvInt("GOMA_REDIS_DB", r.DB),
		TLSConfig: tlsConfig,
	})

	// Test connection
	if err = RedisClient.Ping(ctx).Err(); err != nil {
		logger.Error("Failed to connect to Redis", "error", err)
		return fmt.Errorf("failed to connect to redis: %w", err)
	}

	logger.Info("Successfully initialized Redis client")

	// Initialize rate limiter
	limiter = redis_rate.NewLimiter(RedisClient)

	// Optionally flush DB
	if r.FlushOnStartup {
		if err = RedisClient.FlushDB(ctx).Err(); err != nil {
			logger.Error("Error flushing Redis database", "error", err)
			return fmt.Errorf("failed to flush redis database: %w", err)
		}
		logger.Info("Redis database flushed successfully")
	}

	return nil
}
