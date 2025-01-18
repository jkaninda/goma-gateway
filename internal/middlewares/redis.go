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
	"errors"
	"github.com/go-redis/redis_rate/v10"
	"github.com/redis/go-redis/v9"
)

// redisRateLimiter, handle rateLimit
func redisRateLimiter(clientIP, unit string, rate int) error {
	limit := redis_rate.PerMinute(rate)
	if len(unit) != 0 && unit == "hour" {
		limit = redis_rate.PerHour(rate)
	}
	ctx := context.Background()
	res, err := limiter.Allow(ctx, clientIP, limit)
	if err != nil {
		return err
	}
	if res.Remaining == 0 {
		return errors.New("requests limit exceeded")
	}

	return nil
}
func InitRedis(addr, password string) {
	RedisClient = redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: password,
		DB:       0,
	})
	limiter = redis_rate.NewLimiter(RedisClient)
}
