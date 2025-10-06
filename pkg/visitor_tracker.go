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
	"context"
	"fmt"
	goutils "github.com/jkaninda/go-utils"
	"github.com/redis/go-redis/v9"
	"strings"
	"sync"
	"time"
)

// Visitor represents a tracked visitor
type Visitor struct {
	IP        string    `json:"ip"`
	UserAgent string    `json:"user_agent"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// VisitorTracker manages visitor tracking
type VisitorTracker struct {
	store  VisitorStore
	ttl    time.Duration
	ticker *time.Ticker
	stop   chan struct{}
}

// Config holds configuration for VisitorTracker
type Config struct {
	TTL             time.Duration
	CleanupInterval time.Duration
	Store           VisitorStore
	RedisBased      bool
}

// VisitorStore defines the interface for visitor storage backends
type VisitorStore interface {
	AddVisitor(ctx context.Context, key string, visitor *Visitor) error
	GetVisitor(ctx context.Context, key string) (*Visitor, error)
	UpdateLastSeen(ctx context.Context, key string, lastSeen time.Time) error
	CountVisitors(ctx context.Context) (int, error)
	Cleanup(ctx context.Context, ttl time.Duration) error
	Close() error
}

// MemoryStore implements VisitorStore using in-memory map
type MemoryStore struct {
	visitors map[string]*Visitor
	mu       sync.RWMutex
}

func NewVisitorTracker(config Config) *VisitorTracker {
	vt := &VisitorTracker{
		store:  config.Store,
		ttl:    config.TTL,
		ticker: time.NewTicker(config.CleanupInterval),
		stop:   make(chan struct{}),
	}

	if !redisBased {
		go vt.cleanupJob()
	}
	return vt
}
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		visitors: make(map[string]*Visitor),
	}
}

func (m *MemoryStore) AddVisitor(_ context.Context, key string, visitor *Visitor) error {
	logger.Debug("visitorTracker:: Adding visitor to MemoryStore", "key", key)
	m.mu.Lock()
	defer m.mu.Unlock()

	if existing, exists := m.visitors[key]; exists {
		existing.LastSeen = visitor.LastSeen
		return nil
	}

	m.visitors[key] = visitor
	return nil
}

func (m *MemoryStore) GetVisitor(_ context.Context, key string) (*Visitor, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	visitor, exists := m.visitors[key]
	if !exists {
		return nil, fmt.Errorf("visitor not found")
	}
	return visitor, nil
}

func (m *MemoryStore) UpdateLastSeen(_ context.Context, key string, lastSeen time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if visitor, exists := m.visitors[key]; exists {
		visitor.LastSeen = lastSeen
	}
	return nil
}

func (m *MemoryStore) CountVisitors(ctx context.Context) (int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.visitors), nil
}

func (m *MemoryStore) Cleanup(_ context.Context, ttl time.Duration) error {
	logger.Debug("visitorTracker:: Cleaning up Visitor Cache", "ttl", ttl)
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	for key, visitor := range m.visitors {
		if now.Sub(visitor.LastSeen) > ttl {
			delete(m.visitors, key)
		}
	}
	return nil
}

func (m *MemoryStore) Close() error {
	return nil
}

type RedisStore struct {
	client *redis.Client
}

func NewRedisStore(client *redis.Client) *RedisStore {
	return &RedisStore{
		client: client,
	}
}

func (r *RedisStore) AddVisitor(ctx context.Context, key string, visitor *Visitor) error {
	pipe := r.client.Pipeline()

	logger.Debug("visitorTracker:: Adding visitor to Redis", "key", key)

	// Check if visitor exists
	exists := pipe.Exists(ctx, key)

	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("failed to check visitor existence: %w", err)
	}

	if exists.Val() > 0 {
		logger.Debug("visitorTracker:: Adding visitor to Redis", "key", key, "visitor", visitor)
		return r.UpdateLastSeen(ctx, key, visitor.LastSeen)
	}

	visitorData := map[string]interface{}{
		"IP":        visitor.IP,
		"UserAgent": visitor.UserAgent,
		"FirstSeen": visitor.FirstSeen.Unix(),
		"LastSeen":  visitor.LastSeen.Unix(),
	}

	pipe = r.client.Pipeline()
	pipe.HSet(ctx, key, visitorData)
	pipe.Expire(ctx, key, time.Minute*5) // Set TTL for automatic expiration, 5m
	_, err := pipe.Exec(ctx)
	return err
}

func (r *RedisStore) GetVisitor(ctx context.Context, key string) (*Visitor, error) {
	result := r.client.HGetAll(ctx, key)
	data, err := result.Result()
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("visitor not found")
	}
	visitor := &Visitor{
		IP:        data["IP"],
		UserAgent: data["UserAgent"],
	}
	return visitor, nil
}

func (r *RedisStore) UpdateLastSeen(ctx context.Context, key string, lastSeen time.Time) error {
	return r.client.HSet(ctx, key, "LastSeen", lastSeen.Unix()).Err()
}

func (r *RedisStore) CountVisitors(ctx context.Context) (int, error) {
	logger.Debug("visitorTracker:: Counting visitors in Redis")
	keys, err := r.client.Keys(ctx, fmt.Sprintf("%s*", visitorPrefix)).Result()
	if err != nil {
		return 0, err
	}
	return len(keys), nil
}

func (r *RedisStore) Cleanup(ctx context.Context, ttl time.Duration) error {
	return nil
}

func (r *RedisStore) Close() error {
	return r.client.Close()
}

func (vt *VisitorTracker) AddVisitor(ctx context.Context, ip string, userAgent string) {
	if strings.TrimSpace(ip) == "" || strings.TrimSpace(userAgent) == "" {
		return
	}
	go func(ip, userAgent string) {
		key := generateVisitorID(ip, userAgent)
		now := time.Now()

		visitor := &Visitor{
			IP:        ip,
			UserAgent: userAgent,
			FirstSeen: now,
			LastSeen:  now,
		}
		logger.Debug("VisitorTracker:: Tracking visitor", "ip", ip, "userAgent", userAgent, "key", key)
		if err := vt.store.AddVisitor(ctx, key, visitor); err != nil {
			logger.Error("visitorTracker:: Failed to add visitor", "error", err, "ip", ip)
		}
		vt.updateVisitorCountMetric(ctx)
	}(ip, userAgent)

}

func (vt *VisitorTracker) GetVisitorCount(ctx context.Context) (int, error) {
	return vt.store.CountVisitors(ctx)
}

func (vt *VisitorTracker) updateVisitorCountMetric(ctx context.Context) {
	if prometheusMetrics == nil {
		return
	}
	logger.Debug("visitorTracker:: Updating real-time visitors metric")
	count, err := vt.store.CountVisitors(ctx)
	if err != nil {
		logger.Error("Failed to get visitor count", "error", err)

		return
	}
	prometheusMetrics.GatewayRealTimeVisitorsCount.Set(float64(count))
	logger.Debug("visitorTracker:: Updated real-time visitors metric", "count", count)
}

func (vt *VisitorTracker) cleanupJob() {
	ctx := context.Background()
	for {
		select {
		case <-vt.ticker.C:
			if err := vt.store.Cleanup(ctx, vt.ttl); err != nil {
				logger.Error("visitorTracker:: Cleanup failed", "error", err)
			}
			vt.updateVisitorCountMetric(ctx)
		case <-vt.stop:
			vt.ticker.Stop()
			return
		}
	}
}

func (vt *VisitorTracker) Stop() error {
	close(vt.stop)
	return vt.store.Close()
}

func generateVisitorID(ip string, agent string) string {
	return fmt.Sprintf("%s%s-%s", visitorPrefix, ip, goutils.Slug(agent))
}
