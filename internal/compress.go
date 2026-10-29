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
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	goutils "github.com/jkaninda/go-utils"
	"github.com/jkaninda/goma-gateway/internal/middlewares"
	"gopkg.in/yaml.v3"
)

// Upstream modes for the compress middleware.
const (
	compressUpstreamPassthrough = "passthrough"
	compressUpstreamIdentity    = "identity"
)

// CompressRuleMiddleware is the rule of a `compress` middleware.
//
//	rule:
//	  algorithms: [zstd, br, gzip]
//	  minSize: 1KiB
//	  levels: {gzip: 5, br: 2, zstd: default}
//	  excludedContentTypes: ["application/pdf"]
//	  excludedPaths: ["/login"]
//	  upstream: passthrough
type CompressRuleMiddleware struct {
	// Algorithms lists the codings offered, in server preference order.
	// Default: zstd, br, gzip.
	Algorithms []string `yaml:"algorithms,omitempty" json:"algorithms"`
	// MinSize is the smallest body worth compressing: bytes ("1024") or a
	// size with a unit ("1KiB", "2KB"). Default 1KiB.
	MinSize byteSize `yaml:"minSize,omitempty" json:"minSize"`
	// Levels sets the level per algorithm.
	Levels CompressLevels `yaml:"levels,omitempty" json:"levels"`
	// IncludedContentTypes replaces the built-in list of compressible types.
	IncludedContentTypes []string `yaml:"includedContentTypes,omitempty" json:"includedContentTypes"`
	// ExcludedContentTypes are never compressed.
	ExcludedContentTypes []string `yaml:"excludedContentTypes,omitempty" json:"excludedContentTypes"`
	// ExcludedPaths are never compressed, e.g. pages that reflect user input
	// next to a secret (BREACH).
	ExcludedPaths []string `yaml:"excludedPaths,omitempty" json:"excludedPaths"`
	// Upstream is "passthrough" (default: forward Accept-Encoding, keep a
	// backend-compressed body as is) or "identity" (ask the backend for an
	// uncompressed body and let the gateway compress).
	Upstream string `yaml:"upstream,omitempty" json:"upstream"`
}

// CompressLevels holds the per-algorithm compression levels.
type CompressLevels struct {
	Gzip   int    `yaml:"gzip,omitempty" json:"gzip"` // 1-9, default 5
	Brotli int    `yaml:"br,omitempty" json:"br"`     // 1-11, default 2
	Zstd   string `yaml:"zstd,omitempty" json:"zstd"` // fastest|default|better|best
}

// toConfig validates the rule and turns it into a middleware configuration.
func (c *CompressRuleMiddleware) toConfig() (middlewares.CompressConfig, error) {
	cfg := middlewares.CompressConfig{
		Algorithms:           c.Algorithms,
		GzipLevel:            c.Levels.Gzip,
		BrotliLevel:          c.Levels.Brotli,
		ZstdLevel:            c.Levels.Zstd,
		IncludedContentTypes: c.IncludedContentTypes,
		ExcludedContentTypes: c.ExcludedContentTypes,
		ExcludedPaths:        c.ExcludedPaths,
	}
	if c.MinSize != "" {
		n, err := parseByteSize(string(c.MinSize))
		if err != nil {
			return cfg, fmt.Errorf("invalid minSize %q: %w", c.MinSize, err)
		}
		cfg.MinSize = int(n)
	}
	switch strings.ToLower(strings.TrimSpace(c.Upstream)) {
	case "", compressUpstreamPassthrough:
	case compressUpstreamIdentity:
		cfg.UpstreamIdentity = true
	default:
		return cfg, fmt.Errorf("invalid upstream %q: use %q or %q", c.Upstream, compressUpstreamPassthrough, compressUpstreamIdentity)
	}
	return cfg, nil
}

// byteSize is a size written either as a YAML number (1024) or a string with
// a unit ("1KiB"). Rules reach the middleware through a JSON round trip, so it
// accepts both a JSON number and a JSON string.
type byteSize string

func (b *byteSize) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		*b = byteSize(s)
		return nil
	}
	var n json.Number
	if err := json.Unmarshal(data, &n); err != nil {
		return fmt.Errorf("size must be a number or a string such as \"1KiB\"")
	}
	*b = byteSize(n.String())
	return nil
}

func (b *byteSize) UnmarshalYAML(value *yaml.Node) error {
	*b = byteSize(value.Value)
	return nil
}

// parseByteSize reads a plain byte count or a size with a unit.
func parseByteSize(s string) (int64, error) {
	s = strings.ReplaceAll(strings.TrimSpace(s), " ", "")
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		if n < 0 {
			return 0, fmt.Errorf("must not be negative")
		}
		return n, nil
	}
	return goutils.ConvertToBytes(s)
}

// applyCompressMiddleware configures response compression for the route. It
// registers no router middleware: the compressor wraps the proxy handler in
// configureHandlers, so it always runs innermost.
func applyCompressMiddleware(mid Middleware, r *Route) error {
	logger.Debug("Applying compress middleware", "middleware", mid.Name, "route", r.Name)
	rule := &CompressRuleMiddleware{}
	if mid.Rule != nil {
		if err := goutils.DeepCopy(rule, mid.Rule); err != nil {
			return fmt.Errorf("compress middleware %q: %w", mid.Name, err)
		}
	}
	cfg, err := rule.toConfig()
	if err != nil {
		return fmt.Errorf("compress middleware %q: %w", mid.Name, err)
	}
	if r.compression != nil {
		logger.Warn("Route lists more than one compress middleware; the last one wins",
			"route", r.Name, "middleware", mid.Name)
	}
	routeName := r.Name
	cfg.RoutePath = r.Path
	cfg.Paths = mid.Paths
	cfg.OnCompressed = func(encoding string, in, out int64) {
		if prometheusMetrics == nil {
			return
		}
		prometheusMetrics.GatewayCompressionBytesIn.WithLabelValues(routeName, encoding).Add(float64(in))
		prometheusMetrics.GatewayCompressionBytesOut.WithLabelValues(routeName, encoding).Add(float64(out))
	}
	cfg.OnSkipped = func(reason string) {
		if prometheusMetrics == nil {
			return
		}
		prometheusMetrics.GatewayCompressionSkipped.WithLabelValues(routeName, reason).Inc()
	}
	c, err := middlewares.NewCompressor(cfg)
	if err != nil {
		return fmt.Errorf("compress middleware %q: %w", mid.Name, err)
	}
	r.compression = c
	return nil
}
