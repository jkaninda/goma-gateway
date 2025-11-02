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
	"github.com/go-redis/redis_rate/v10"
	"github.com/jkaninda/goma-gateway/internal/config"
	logger2 "github.com/jkaninda/logger"
	"github.com/redis/go-redis/v9"
	"regexp"
)

const (
	GomaAccessToken  = "goma_access_token"
	GomaRefreshToken = "goma_refresh_token"
)

var (
	sqlPatterns       = regexp.MustCompile(`(?i)\b(union|select|drop|insert|delete|update|create|alter|exec)\b|;|--`)
	traversalPatterns = regexp.MustCompile(`(?i)(\.\./|\\.\\|%2e%2e%2f|%2e%2e%5c|%252e%252e%252f|%252e%252e%255c)`)
	xssPatterns       = regexp.MustCompile(`(?i)(<script.*?>|<\/script>|on\w+\s*=|javascript:)`)
)

var (
	RedisClient        *redis.Client
	TrustedProxyConfig *config.ProxyConfig
	limiter            *redis_rate.Limiter
	logger             = logger2.Default()
	jwtAlgo            = []string{"RS256", "HS256", "ES256"}
)
