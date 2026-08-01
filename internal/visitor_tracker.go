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
	"strconv"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

// VisitorTracker feeds the gateway's real-time visitors gauge: how many distinct
// visitors have been seen within the TTL. One tracker serves the whole gateway —
// the gauge is gateway-wide, and it survives config reloads, so it must not be
// built per route.
//
// The request path only enqueues a visitor id; a single background goroutine
// owns every store call, batching what has piled up into one write and sweeping
// expired visitors on a ticker. Nothing on the hot path talks to Redis, and a
// burst costs a dropped sample rather than a slow response.
//
// Visitors are keyed on the same daily-salted hash the analytics stream uses, so
// no client IP is written to the store.
type VisitorTracker struct {
	store      VisitorStore
	ttl        time.Duration
	sweepEvery time.Duration

	queue   chan string
	stop    chan struct{}
	done    chan struct{}
	stopped sync.Once
}

// Config holds configuration for VisitorTracker.
type Config struct {
	// TTL is how long a visitor stays "active" after their last request.
	TTL time.Duration
	// CleanupInterval is how often expired visitors are swept and the gauge is
	// republished — so it also sets how fresh the gauge is.
	CleanupInterval time.Duration
	Store           VisitorStore
}

// VisitorStore holds the set of recently-active visitor ids. Implementations are
// called from one goroutine only.
type VisitorStore interface {
	// Touch records ids as active at seen.
	Touch(ctx context.Context, ids []string, seen time.Time) error
	// Count returns the distinct visitors active at or after since.
	Count(ctx context.Context, since time.Time) (int, error)
	// Sweep drops visitors last seen before the given time.
	Sweep(ctx context.Context, before time.Time) error
	Close() error
}

const (
	// visitorQueueSize absorbs bursts between store writes. Full means the
	// gateway is taking requests faster than the store can record them, and a
	// sample is dropped — the gauge is a sample of activity, not a ledger.
	visitorQueueSize = 4096
	// visitorBatchSize bounds how many ids go into a single store write.
	visitorBatchSize = 512

	// defaultVisitorTTL spans the gap between a visitor's requests rather than
	// their visit.
	defaultVisitorTTL   = 5 * time.Minute
	minVisitorTTL       = defaultVisitorSweep
	defaultVisitorSweep = 30 * time.Second
)

func NewVisitorTracker(config Config) *VisitorTracker {
	if config.Store == nil {
		return nil
	}
	vt := &VisitorTracker{
		store:      config.Store,
		ttl:        config.TTL,
		sweepEvery: config.CleanupInterval,
		queue:      make(chan string, visitorQueueSize),
		stop:       make(chan struct{}),
		done:       make(chan struct{}),
	}
	if vt.ttl <= 0 {
		vt.ttl = defaultVisitorTTL
	}
	if vt.sweepEvery <= 0 {
		vt.sweepEvery = defaultVisitorSweep
	}
	go vt.run()
	return vt
}

// AddVisitor records a request's visitor. Safe to call from every request: it
// hashes the identity and hands it to the background writer without blocking,
// and does nothing at all when the tracker is nil (metrics disabled).
func (vt *VisitorTracker) AddVisitor(ip, userAgent string) {
	if vt == nil || ip == "" {
		return
	}
	select {
	case vt.queue <- visitorID(ip, userAgent):
	default:
		// Queue full — drop rather than block a response on the gauge.
	}
}

// GetVisitorCount returns the distinct visitors active within the TTL.
func (vt *VisitorTracker) GetVisitorCount(ctx context.Context) (int, error) {
	if vt == nil {
		return 0, nil
	}
	return vt.store.Count(ctx, time.Now().Add(-vt.ttl))
}

// run owns the store: it batches queued ids into single writes, and on each tick
// sweeps expired visitors and republishes the gauge.
func (vt *VisitorTracker) run() {
	defer close(vt.done)
	ticker := time.NewTicker(vt.sweepEvery)
	defer ticker.Stop()
	ctx := context.Background()

	for {
		select {
		case id := <-vt.queue:
			vt.write(ctx, vt.drain(id))
		case <-ticker.C:
			vt.sweep(ctx)
		case <-vt.stop:
			// Record whatever is still queued, so a shutdown doesn't lose the
			// last few seconds of activity from a shared store.
			if batch := vt.drain(); len(batch) > 0 {
				vt.write(ctx, batch)
			}
			return
		}
	}
}

// drain collects everything already queued (starting from any ids already in
// hand), up to the batch size, without waiting for more.
func (vt *VisitorTracker) drain(seed ...string) []string {
	batch := make([]string, 0, len(seed)+16)
	batch = append(batch, seed...)
	for len(batch) < visitorBatchSize {
		select {
		case id := <-vt.queue:
			batch = append(batch, id)
		default:
			return batch
		}
	}
	return batch
}

func (vt *VisitorTracker) write(ctx context.Context, ids []string) {
	if len(ids) == 0 {
		return
	}
	if err := vt.store.Touch(ctx, ids, time.Now()); err != nil {
		logger.Error("visitorTracker:: Failed to record visitors", "error", err, "count", len(ids))
	}
}

func (vt *VisitorTracker) sweep(ctx context.Context) {
	cutoff := time.Now().Add(-vt.ttl)
	if err := vt.store.Sweep(ctx, cutoff); err != nil {
		logger.Error("visitorTracker:: Sweep failed", "error", err)
	}
	if prometheusMetrics == nil {
		return
	}
	count, err := vt.store.Count(ctx, cutoff)
	if err != nil {
		logger.Error("visitorTracker:: Failed to count visitors", "error", err)
		return
	}
	prometheusMetrics.GatewayRealTimeVisitorsCount.Set(float64(count))
	logger.Debug("visitorTracker:: Updated real-time visitors metric", "count", count)
}

// Stop shuts the background writer down. Safe to call more than once.
func (vt *VisitorTracker) Stop() error {
	if vt == nil {
		return nil
	}
	vt.stopped.Do(func() {
		close(vt.stop)
		<-vt.done
	})
	return vt.store.Close()
}

// MemoryStore keeps active visitors in process. Counts are per gateway instance,
// so a multi-replica deployment wanting one number needs the Redis store.
type MemoryStore struct {
	mu   sync.RWMutex
	seen map[string]time.Time
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{seen: make(map[string]time.Time)}
}

func (m *MemoryStore) Touch(_ context.Context, ids []string, seen time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, id := range ids {
		m.seen[id] = seen
	}
	return nil
}

// Count filters by last-seen rather than returning the map size, so it is exact
// between sweeps instead of counting visitors who have already gone stale.
func (m *MemoryStore) Count(_ context.Context, since time.Time) (int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	n := 0
	for _, ts := range m.seen {
		if !ts.Before(since) {
			n++
		}
	}
	return n, nil
}

func (m *MemoryStore) Sweep(_ context.Context, before time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, ts := range m.seen {
		if ts.Before(before) {
			delete(m.seen, id)
		}
	}
	return nil
}

func (m *MemoryStore) Close() error { return nil }

// RedisStore keeps active visitors in one sorted set — member = visitor id,
// score = last-seen unix seconds — so every replica behind the same Redis agrees
// on one number. Counting is a range query and expiry a range delete; both are
// O(log N), where a key-per-visitor layout could only be counted by scanning the
// keyspace.
type RedisStore struct {
	client *redis.Client
}

// visitorSetKey is the single sorted set holding active visitors.
const visitorSetKey = "goma:visitors:active"

func NewRedisStore(client *redis.Client) *RedisStore {
	return &RedisStore{client: client}
}

func (r *RedisStore) Touch(ctx context.Context, ids []string, seen time.Time) error {
	if len(ids) == 0 {
		return nil
	}
	members := make([]redis.Z, 0, len(ids))
	for _, id := range ids {
		members = append(members, redis.Z{Score: float64(seen.Unix()), Member: id})
	}
	pipe := r.client.Pipeline()
	pipe.ZAdd(ctx, visitorSetKey, members...)
	// A whole-set TTL is the backstop that drops the key if this gateway stops
	// sweeping (crash, shutdown) — the sweep is what keeps it trimmed normally.
	pipe.Expire(ctx, visitorSetKey, time.Hour)
	_, err := pipe.Exec(ctx)
	return err
}

func (r *RedisStore) Count(ctx context.Context, since time.Time) (int, error) {
	n, err := r.client.ZCount(ctx, visitorSetKey, strconv.FormatInt(since.Unix(), 10), "+inf").Result()
	if err == redis.Nil {
		return 0, nil
	}
	return int(n), err
}

func (r *RedisStore) Sweep(ctx context.Context, before time.Time) error {
	err := r.client.ZRemRangeByScore(ctx, visitorSetKey, "-inf", "("+strconv.FormatInt(before.Unix(), 10)).Err()
	if err == redis.Nil {
		return nil
	}
	return err
}

// Close does not close the client: it is the gateway-wide Redis connection,
// shared with rate limiting, the HTTP cache and the analytics stream.
func (r *RedisStore) Close() error { return nil }
