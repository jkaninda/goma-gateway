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
	"github.com/redis/go-redis/v9"
)

// sqlPatterns contains SQL injections patters
const sqlPatterns = `(?i)(union|select|drop|insert|delete|update|create|alter|exec|;|--)`
const traversalPatterns = `\.\./`
const _traversalPatterns = `\..\../`
const xssPatterns = `(?i)<script|onerror|onload`

var (
	RedisClient *redis.Client
	limiter     *redis_rate.Limiter
)

// Paths of known bot user agents
var botUserAgents = []string{
	"Googlebot",
	"Bingbot",
	"Slurp",
	"Yahoo",
	"YandexBot",
	"Yeti",
	"AhrefsBot",
	"SemrushBot",
	"DotBot",
	"Exabot",
	"facebot",
	"ia_archiver",
	"MJ12bot",
	"Bytespider",
	"archive.org_bot",
}
