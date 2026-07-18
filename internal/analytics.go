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
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	mrand "math/rand"
	"net/url"
	"strconv"
	"sync"
	"time"

	goutils "github.com/jkaninda/go-utils"
	"github.com/jkaninda/goma-gateway/internal/middlewares"
	"github.com/redis/go-redis/v9"
)

// AnalyticsEvent is one request, emitted to Miabi for web-analytics rollups.
// It carries NO raw client IP: only a daily-salted visitor id
// and, optionally, a country resolved at the edge.
type AnalyticsEvent struct {
	Ts           int64  `json:"ts"` // unix millis
	Gateway      string `json:"gw,omitempty"`
	Route        string `json:"name"`
	Host         string `json:"host"`
	Method       string `json:"method"`
	Status       int    `json:"status"`
	Path         string `json:"path,omitempty"`
	PathTemplate string `json:"path_template,omitempty"`
	ReqBytes     int64  `json:"req_bytes"`
	RespBytes    int64  `json:"resp_bytes"`
	DurationMs   int64  `json:"duration_ms"`
	UpstreamMs   int64  `json:"upstream_ms"`
	VID          string `json:"vid"`               // daily-salted hash(IP+UA) — NOT the IP
	Country      string `json:"country,omitempty"` // optional GeoIP; "" when no DB wired
	UA           string `json:"ua,omitempty"`      // raw UA; Miabi parses family/os/device/bot
	RefererHost  string `json:"referer_host,omitempty"`
}

// analyticsEmitter is a non-blocking Redis-Stream writer. It never blocks or
// fails a request: emit drops on a full buffer, and a background goroutine
// pipelines XADDs with an approximate MAXLEN cap so a lagging consumer can't
// grow Redis unbounded.
type analyticsEmitter struct {
	stream    string
	maxLen    int64
	sample    float64
	gatewayID string
	ch        chan *AnalyticsEvent
	client    *redis.Client
}

// analytics is the package-global emitter, nil unless initAnalytics enabled it.
var analytics *analyticsEmitter

// initAnalytics wires the emitter from the environment. No-op unless enabled
// AND Redis is configured (the transport). Call it at boot after initRedis.
func initAnalytics() {
	if goutils.Env("GOMA_ANALYTICS_ENABLED", "false") != "true" {
		return
	}
	if !redisBased || middlewares.RedisClient == nil {
		logger.Warn("Analytics enabled but Redis is not configured; analytics disabled")
		return
	}
	initGeoIP() // optional country enrichment from /etc/goma (GOMA_GEOIP_DB)
	sample := 1.0
	if v, err := strconv.ParseFloat(goutils.Env("GOMA_ANALYTICS_SAMPLE", "1"), 64); err == nil {
		sample = v
	}
	maxLen := int64(1_000_000)
	if v, err := strconv.ParseInt(goutils.Env("GOMA_ANALYTICS_MAXLEN", "1000000"), 10, 64); err == nil && v > 0 {
		maxLen = v
	}
	analytics = &analyticsEmitter{
		stream:    goutils.Env("GOMA_ANALYTICS_STREAM", "goma:analytics"),
		maxLen:    maxLen,
		sample:    sample,
		gatewayID: goutils.Env("GOMA_GATEWAY_ID", ""),
		client:    middlewares.RedisClient,
		ch:        make(chan *AnalyticsEvent, 8192),
	}
	go analytics.run()
	logger.Info("Goma analytics enabled", "stream", analytics.stream, "sample", sample)
}

// sampled decides (cheaply, before the event is built) whether to record this one.
func (a *analyticsEmitter) sampled() bool {
	if a.sample <= 0 || a.sample >= 1 {
		return true
	}
	return mrand.Float64() < a.sample
}

// emit is non-blocking: a full buffer drops the event. Analytics must never add
// latency or backpressure to the request path.
func (a *analyticsEmitter) emit(e *AnalyticsEvent) {
	select {
	case a.ch <- e:
	default:
	}
}

// run batches events and pipelines XADDs with an approximate MAXLEN cap. Errors
// are swallowed — analytics never surfaces to a user request.
func (a *analyticsEmitter) run() {
	ctx := context.Background()
	batch := make([]*AnalyticsEvent, 0, 256)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		pipe := a.client.Pipeline()
		for _, e := range batch {
			b, err := json.Marshal(e)
			if err != nil {
				continue
			}
			pipe.XAdd(ctx, &redis.XAddArgs{
				Stream: a.stream,
				MaxLen: a.maxLen,
				Approx: true,
				Values: map[string]any{"e": b},
			})
		}
		_, _ = pipe.Exec(ctx)
		batch = batch[:0]
	}
	t := time.NewTicker(250 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case e := <-a.ch:
			batch = append(batch, e)
			if len(batch) >= 256 {
				flush()
			}
		case <-t.C:
			flush()
		}
	}
}

var (
	saltMu  sync.Mutex
	saltDay string
	saltVal string
)

// dailySalt returns a salt that is stable for the UTC day and shared across all
// gateways (SETNX into Redis), so the same visitor gets the same VID on every
// edge gateway that day — correct cross-gateway unique counting — while a new
// day's salt makes VIDs unlinkable across days (no long-term tracking). Cached
// in-process; touches Redis once per day.
func dailySalt() string {
	day := time.Now().UTC().Format("2006-01-02")
	saltMu.Lock()
	defer saltMu.Unlock()
	if saltDay == day && saltVal != "" {
		return saltVal
	}
	buf := make([]byte, 16)
	_, _ = rand.Read(buf)
	cand := hex.EncodeToString(buf)
	if middlewares.RedisClient != nil {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		key := "goma:analytics:salt:" + day
		_ = middlewares.RedisClient.SetNX(ctx, key, cand, 48*time.Hour).Err()
		if v, err := middlewares.RedisClient.Get(ctx, key).Result(); err == nil && v != "" {
			cand = v
		}
	}
	saltDay, saltVal = day, cand
	return cand
}

// visitorID hashes (dailySalt, IP, UA). The raw IP never leaves this function.
func visitorID(ip, ua string) string {
	sum := sha256.Sum256([]byte(dailySalt() + "|" + ip + "|" + ua))
	return hex.EncodeToString(sum[:8])
}

// (geoCountry lives in geoip.go — it resolves the IP to a country at the edge,
// then the caller discards the IP.)

// refererHost reduces a referer to its host — a referer path/query can carry
// tokens, so only the host is emitted.
func refererHost(ref string) string {
	if ref == "" {
		return ""
	}
	if u, err := url.Parse(ref); err == nil {
		return u.Host
	}
	return ""
}
