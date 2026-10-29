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
	"bufio"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/gzip"
	"github.com/klauspost/compress/zstd"
)

// Compression defaults.
const (
	DefaultCompressMinSize  = 1024
	DefaultGzipLevel        = 5
	DefaultBrotliLevel      = 2
	DefaultZstdLevel        = "default"
	zstdWindowSize          = 1 << 20 // keeps per-encoder memory small; RFC 8878 caps HTTP at 8 MiB
	brotliWindowBits        = 19      // 512 KiB, as nginx; the 4 MiB default held ~9 MiB per in-flight response
	compressHeaderIndicator = "X-Goma-Compression"
)

// Reasons a response is sent without compression, used as a metric label.
const (
	SkipReasonIdentity    = "client_identity"
	SkipReasonMethod      = "method"
	SkipReasonRange       = "range"
	SkipReasonStatus      = "status"
	SkipReasonEncoded     = "already_encoded"
	SkipReasonNoTransform = "no_transform"
	SkipReasonType        = "content_type"
	SkipReasonSize        = "too_small"
	SkipReasonPath        = "excluded_path"
	SkipReasonUpgrade     = "upgrade"
)

// DefaultCompressAlgorithms is the server preference used when none is set.
var DefaultCompressAlgorithms = []string{EncodingZstd, EncodingBrotli, EncodingGzip}

// defaultCompressibleTypes is the built-in list of media types worth
// compressing. Already-compressed formats (images other than SVG, video,
// audio, archives, woff/woff2) are left out on purpose.
var defaultCompressibleTypes = []string{
	"text/*",
	"application/json",
	"application/*+json",
	"application/x-ndjson",
	"application/javascript",
	"application/x-javascript",
	"application/ecmascript",
	"application/xml",
	"application/*+xml",
	"application/yaml",
	"application/x-yaml",
	"application/toml",
	"application/graphql",
	"application/wasm",
	"application/x-www-form-urlencoded",
	"application/vnd.ms-fontobject",
	"application/x-font-ttf",
	"font/ttf",
	"font/otf",
	"image/svg+xml",
	"image/x-icon",
	"image/vnd.microsoft.icon",
	"image/bmp",
}

// neverCompressTypes are streamed protocols that break when a coding is
// applied, whatever the configuration says.
var neverCompressTypes = []string{
	"text/event-stream",
	"application/grpc",
	"application/grpc+*",
	"application/grpc-web",
	"application/grpc-web+*",
	"application/grpc-web-text",
	"application/grpc-web-text+*",
}

// CompressConfig configures the compression middleware.
type CompressConfig struct {
	// RoutePath and Paths scope the middleware like other path-aware
	// middlewares; no Paths means every request on the route.
	RoutePath string
	Paths     []string
	// Algorithms lists the codings to offer, in server preference order.
	Algorithms []string
	// MinSize is the smallest body, in bytes, worth compressing.
	MinSize int
	// GzipLevel 1-9, BrotliLevel 0-11, ZstdLevel fastest|default|better|best.
	GzipLevel   int
	BrotliLevel int
	ZstdLevel   string
	// IncludedContentTypes replaces the built-in list when set.
	IncludedContentTypes []string
	// ExcludedContentTypes are never compressed.
	ExcludedContentTypes []string
	// ExcludedPaths are never compressed (BREACH-sensitive pages).
	ExcludedPaths []string
	// UpstreamIdentity asks the backend for an uncompressed body, so the
	// gateway owns the coding and backends spend no CPU on it.
	UpstreamIdentity bool
	// OnCompressed and OnSkipped feed metrics; both may be nil.
	OnCompressed func(encoding string, in, out int64)
	OnSkipped    func(reason string)
}

// Compressor is the compression middleware.
type Compressor struct {
	cfg      CompressConfig
	included []string
	excluded []string
	pools    map[string]*encoderPool
}

// NewCompressor validates cfg, applies defaults and returns the middleware.
func NewCompressor(cfg CompressConfig) (*Compressor, error) {
	if len(cfg.Algorithms) == 0 {
		cfg.Algorithms = slices.Clone(DefaultCompressAlgorithms)
	}
	seen := map[string]bool{}
	algorithms := make([]string, 0, len(cfg.Algorithms))
	for _, a := range cfg.Algorithms {
		a = strings.ToLower(strings.TrimSpace(a))
		if a == "brotli" {
			a = EncodingBrotli
		}
		if !IsSupportedEncoding(a) {
			return nil, fmt.Errorf("compress: unsupported algorithm %q (supported: zstd, br, gzip)", a)
		}
		if !seen[a] {
			seen[a] = true
			algorithms = append(algorithms, a)
		}
	}
	cfg.Algorithms = algorithms

	if cfg.MinSize < 0 {
		return nil, fmt.Errorf("compress: minSize must not be negative")
	}
	if cfg.MinSize == 0 {
		cfg.MinSize = DefaultCompressMinSize
	}
	if cfg.GzipLevel == 0 {
		cfg.GzipLevel = DefaultGzipLevel
	}
	if cfg.GzipLevel < gzip.BestSpeed || cfg.GzipLevel > gzip.BestCompression {
		return nil, fmt.Errorf("compress: gzip level %d out of range (1-9)", cfg.GzipLevel)
	}
	if cfg.BrotliLevel == 0 {
		cfg.BrotliLevel = DefaultBrotliLevel
	}
	if cfg.BrotliLevel < brotli.BestSpeed || cfg.BrotliLevel > brotli.BestCompression {
		return nil, fmt.Errorf("compress: brotli level %d out of range (0-11)", cfg.BrotliLevel)
	}
	if cfg.ZstdLevel == "" {
		cfg.ZstdLevel = DefaultZstdLevel
	}
	zl, err := parseZstdLevel(cfg.ZstdLevel)
	if err != nil {
		return nil, err
	}

	included := cfg.IncludedContentTypes
	if len(included) == 0 {
		included = defaultCompressibleTypes
	}
	c := &Compressor{
		cfg:      cfg,
		included: normalizeTypes(included),
		excluded: normalizeTypes(append(slices.Clone(cfg.ExcludedContentTypes), neverCompressTypes...)),
		pools:    make(map[string]*encoderPool, len(algorithms)),
	}
	for _, a := range algorithms {
		switch a {
		case EncodingGzip:
			c.pools[a] = sharedPool(fmt.Sprintf("gzip-%d", cfg.GzipLevel), newGzipEncoder(cfg.GzipLevel))
		case EncodingBrotli:
			c.pools[a] = sharedPool(fmt.Sprintf("br-%d", cfg.BrotliLevel), newBrotliEncoder(cfg.BrotliLevel))
		case EncodingZstd:
			c.pools[a] = sharedPool(fmt.Sprintf("zstd-%d", zl), newZstdEncoder(zl))
		}
	}
	return c, nil
}

func parseZstdLevel(s string) (zstd.EncoderLevel, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "fastest":
		return zstd.SpeedFastest, nil
	case "default":
		return zstd.SpeedDefault, nil
	case "better":
		return zstd.SpeedBetterCompression, nil
	case "best":
		return zstd.SpeedBestCompression, nil
	}
	return 0, fmt.Errorf("compress: zstd level %q must be fastest, default, better or best", s)
}

// Algorithms returns the codings offered, in preference order.
func (c *Compressor) Algorithms() []string { return slices.Clone(c.cfg.Algorithms) }

// Middleware compresses eligible responses produced by next.
func (c *Compressor) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isGuardedPathMatching(r.URL.Path, c.cfg.RoutePath, c.cfg.Paths) {
			next.ServeHTTP(w, r)
			return
		}
		if len(c.cfg.ExcludedPaths) > 0 && isPathMatching(r.URL.Path, c.cfg.RoutePath, c.cfg.ExcludedPaths) {
			c.skipped(SkipReasonPath)
			next.ServeHTTP(w, r)
			return
		}
		if headerContainsToken(r.Header, "Connection", "upgrade") || r.Header.Get("Upgrade") != "" {
			c.skipped(SkipReasonUpgrade)
			next.ServeHTTP(w, r)
			return
		}

		// A compressed response carries a weakened ETag, which the client sends back; the backend only
		// knows the strong one, so without this every revalidation would return the full body.
		strengthenIfNoneMatch(r.Header)

		encoding := NegotiateEncoding(r, c.cfg.Algorithms)
		reason := ""
		switch {
		case r.Method == http.MethodHead || r.Method == http.MethodConnect:
			reason = SkipReasonMethod
		case r.Header.Get("Range") != "":
			reason = SkipReasonRange
		case encoding == EncodingIdentity:
			reason = SkipReasonIdentity
		}

		if c.cfg.UpstreamIdentity && reason != SkipReasonRange {
			// An explicit identity (not a deleted header) keeps Go's transport
			// from adding its own Accept-Encoding: gzip and inflating the body
			// on the way in.
			r.Header.Set("Accept-Encoding", EncodingIdentity)
		}

		cw := &compressWriter{rw: w, c: c, req: r, encoding: encoding, skipReason: reason, status: http.StatusOK}
		defer cw.close()
		next.ServeHTTP(cw, r)
	})
}

func (c *Compressor) skipped(reason string) {
	if c.cfg.OnSkipped != nil {
		c.cfg.OnSkipped(reason)
	}
}

// compressWriter decides, once it has seen the response headers and enough of
// the body, whether to compress, and then either streams through an encoder or
// writes the body untouched.
type compressWriter struct {
	rw       http.ResponseWriter
	c        *Compressor
	req      *http.Request
	encoding string
	// skipReason, when set before the response starts, rules compression out.
	skipReason string

	status      int
	wroteHeader bool // the handler's status is recorded
	decided     bool // the status and headers have been sent downstream
	compressing bool
	hijacked    bool

	buf     []byte // body held back until MinSize is reached
	enc     encoder
	pool    *encoderPool
	counter countingWriter
	in      int64
}

func (cw *compressWriter) Header() http.Header { return cw.rw.Header() }

func (cw *compressWriter) WriteHeader(code int) {
	if cw.wroteHeader || cw.hijacked {
		return
	}
	// Informational responses (103 Early Hints) go straight out; the final
	// status is still to come.
	if code >= 100 && code < 200 && code != http.StatusSwitchingProtocols {
		cw.rw.WriteHeader(code)
		return
	}
	cw.status = code
	cw.wroteHeader = true

	h := cw.rw.Header()
	compressible := cw.compressibleType(h)
	if compressible {
		addVary(h, "Accept-Encoding")
	}
	if reason := cw.eligibility(h, compressible); reason != "" {
		cw.decide(false, reason)
		return
	}
	// A declared length settles the question now; otherwise hold the start of
	// the body until MinSize is reached or the handler finishes.
	if cl := h.Get("Content-Length"); cl != "" {
		if n, err := parseContentLength(cl); err == nil {
			cw.decide(n >= int64(cw.c.cfg.MinSize), SkipReasonSize)
		}
	}
}

// eligibility returns why this response must not be compressed, or "".
func (cw *compressWriter) eligibility(h http.Header, compressible bool) string {
	switch {
	case cw.skipReason != "":
		return cw.skipReason
	case cw.status < 200 || cw.status == http.StatusNoContent || cw.status == http.StatusNotModified ||
		cw.status == http.StatusPartialContent || cw.status == http.StatusSwitchingProtocols:
		return SkipReasonStatus
	case h.Get("Content-Encoding") != "" && !strings.EqualFold(h.Get("Content-Encoding"), EncodingIdentity):
		return SkipReasonEncoded
	case headerContainsToken(h, "Cache-Control", "no-transform"):
		return SkipReasonNoTransform
	case h.Get("Content-Range") != "":
		return SkipReasonRange
	case !compressible:
		return SkipReasonType
	}
	return ""
}

// compressibleType reports whether the response's media type is one to
// compress. A response without a Content-Type is left alone: net/http would
// sniff it from the very bytes we are about to encode.
func (cw *compressWriter) compressibleType(h http.Header) bool {
	ct := h.Get("Content-Type")
	if ct == "" {
		return false
	}
	mediaType, _, err := mime.ParseMediaType(ct)
	if err != nil {
		mediaType = strings.ToLower(strings.TrimSpace(strings.Split(ct, ";")[0]))
	}
	if matchesAnyType(mediaType, cw.c.excluded) {
		return false
	}
	return matchesAnyType(mediaType, cw.c.included)
}

// decide sends the status and headers downstream, with or without an encoder.
func (cw *compressWriter) decide(compress bool, reason string) {
	if cw.decided {
		return
	}
	cw.decided = true
	h := cw.rw.Header()
	if compress {
		h.Set("Content-Encoding", cw.encoding)
		h.Del("Content-Length")
		h.Del("Accept-Ranges") // byte ranges of the encoded body are not ranges of the resource
		weakenETag(h)
		h.Set(compressHeaderIndicator, cw.encoding)
		cw.compressing = true
		cw.pool = cw.c.pools[cw.encoding]
		cw.counter.w = cw.rw
		cw.enc = cw.pool.get(&cw.counter)
	} else {
		cw.c.skipped(reason)
	}
	cw.rw.WriteHeader(cw.status)

	if len(cw.buf) > 0 {
		buffered := cw.buf
		cw.buf = nil
		_, _ = cw.writeDecided(buffered)
	}
}

func (cw *compressWriter) Write(p []byte) (int, error) {
	if cw.hijacked {
		return 0, http.ErrHijacked
	}
	if !cw.wroteHeader {
		h := cw.rw.Header()
		if h.Get("Content-Type") == "" && h.Get("Content-Encoding") == "" && len(p) > 0 {
			// The same sniff net/http performs on the first write, done here
			// so the type is known before deciding.
			h.Set("Content-Type", http.DetectContentType(p))
		}
		cw.WriteHeader(http.StatusOK)
	}
	if cw.decided {
		return cw.writeDecided(p)
	}
	if len(cw.buf)+len(p) >= cw.c.cfg.MinSize {
		// Enough to decide: send what is held, then p straight through,
		// without copying p into the hold buffer first.
		cw.decide(true, "")
		return cw.writeDecided(p)
	}
	if cw.buf == nil {
		cw.buf = make([]byte, 0, cw.c.cfg.MinSize)
	}
	cw.buf = append(cw.buf, p...)
	return len(p), nil
}

func (cw *compressWriter) writeDecided(p []byte) (int, error) {
	if !cw.compressing {
		return cw.rw.Write(p)
	}
	cw.in += int64(len(p))
	return cw.enc.Write(p)
}

// Flush pushes buffered and encoded bytes to the client. A flush before the
// size threshold is reached means the handler is streaming, so the stream is
// compressed from here on: each flush emits a complete, decodable block.
func (cw *compressWriter) Flush() {
	if cw.hijacked {
		return
	}
	if !cw.wroteHeader {
		cw.WriteHeader(http.StatusOK)
	}
	if !cw.decided {
		cw.decide(true, "")
	}
	if cw.compressing {
		_ = cw.enc.Flush()
	}
	_ = http.NewResponseController(cw.rw).Flush()
}

// FlushError is the error-returning form used by http.ResponseController.
func (cw *compressWriter) FlushError() error {
	cw.Flush()
	return nil
}

// Unwrap lets http.ResponseController reach the connection for deadlines.
func (cw *compressWriter) Unwrap() http.ResponseWriter { return cw.rw }

// Hijack hands the connection over; nothing more is written through cw.
func (cw *compressWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	conn, brw, err := http.NewResponseController(cw.rw).Hijack()
	if err == nil {
		cw.hijacked = true
	}
	return conn, brw, err
}

// close finishes the response once the handler returns.
func (cw *compressWriter) close() {
	if cw.hijacked {
		return
	}
	if !cw.wroteHeader {
		return // nothing written: net/http sends the default response
	}
	if !cw.decided {
		// The whole body fitted under MinSize: send it as it is, with its
		// length, since it is all in hand.
		if cw.rw.Header().Get("Content-Length") == "" {
			cw.rw.Header().Set("Content-Length", fmt.Sprint(len(cw.buf)))
		}
		cw.decide(false, SkipReasonSize)
		return
	}
	if cw.compressing {
		_ = cw.enc.Close()
		cw.pool.put(cw.enc)
		cw.enc = nil
		if cw.c.cfg.OnCompressed != nil {
			cw.c.cfg.OnCompressed(cw.encoding, cw.in, cw.counter.n)
		}
	}
}

// countingWriter counts the encoded bytes handed downstream.
type countingWriter struct {
	w io.Writer
	n int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}

// encoder is the common surface of the gzip, zstd and brotli writers.
type encoder interface {
	io.WriteCloser
	Flush() error
	Reset(io.Writer)
}

type zstdEncoder struct{ *zstd.Encoder }

func (z zstdEncoder) Reset(w io.Writer) { z.Encoder.Reset(w) }

type encoderPool struct{ p sync.Pool }

func (ep *encoderPool) get(w io.Writer) encoder {
	e := ep.p.Get().(encoder)
	e.Reset(w)
	return e
}

func (ep *encoderPool) put(e encoder) {
	e.Reset(io.Discard) // drop the reference to the response writer
	ep.p.Put(e)
}

var (
	sharedPoolsMu sync.Mutex
	sharedPools   = map[string]*encoderPool{}
)

// sharedPool returns the process-wide pool for an algorithm and level, so
// routes configured alike share warm encoders.
func sharedPool(key string, newEncoder func() encoder) *encoderPool {
	sharedPoolsMu.Lock()
	defer sharedPoolsMu.Unlock()
	if p, ok := sharedPools[key]; ok {
		return p
	}
	p := &encoderPool{}
	p.p.New = func() any { return newEncoder() }
	sharedPools[key] = p
	return p
}

func newGzipEncoder(level int) func() encoder {
	return func() encoder {
		w, err := gzip.NewWriterLevel(io.Discard, level)
		if err != nil { // level is validated in NewCompressor
			panic(err)
		}
		return w
	}
}

func newBrotliEncoder(level int) func() encoder {
	return func() encoder {
		return brotli.NewWriterOptions(io.Discard, brotli.WriterOptions{Quality: level, LGWin: brotliWindowBits})
	}
}

func newZstdEncoder(level zstd.EncoderLevel) func() encoder {
	return func() encoder {
		e, err := zstd.NewWriter(io.Discard,
			zstd.WithEncoderLevel(level),
			zstd.WithEncoderConcurrency(1),
			zstd.WithWindowSize(zstdWindowSize),
			zstd.WithLowerEncoderMem(true),
			zstd.WithZeroFrames(true),
		)
		if err != nil {
			panic(err)
		}
		return zstdEncoder{e}
	}
}

// addVary appends field to Vary unless it is already listed (or Vary is *).
func addVary(h http.Header, field string) {
	for _, v := range h.Values("Vary") {
		for _, part := range strings.Split(v, ",") {
			p := strings.TrimSpace(part)
			if p == "*" || strings.EqualFold(p, field) {
				return
			}
		}
	}
	h.Add("Vary", field)
}

// strengthenIfNoneMatch drops the W/ prefix from If-None-Match entity tags. If-None-Match uses weak
// comparison (RFC 9110 §13.1.2), so a backend that issued W/"x" itself still matches "x".
func strengthenIfNoneMatch(h http.Header) {
	values := h.Values("If-None-Match")
	if len(values) == 0 {
		return
	}
	tags := make([]string, 0, len(values))
	changed := false
	for _, v := range values {
		for _, tag := range strings.Split(v, ",") {
			tag = strings.TrimSpace(tag)
			if strings.HasPrefix(tag, "W/") {
				tag, changed = tag[2:], true
			}
			if tag != "" {
				tags = append(tags, tag)
			}
		}
	}
	if changed {
		h.Set("If-None-Match", strings.Join(tags, ", "))
	}
}

// weakenETag turns a strong validator into a weak one: the encoded bytes
// differ from the identity body the backend's ETag describes (RFC 9110 §8.8.3).
func weakenETag(h http.Header) {
	if etag := h.Get("ETag"); etag != "" && !strings.HasPrefix(etag, "W/") {
		h.Set("ETag", "W/"+etag)
	}
}

func headerContainsToken(h http.Header, name, token string) bool {
	for _, v := range h.Values(name) {
		for _, part := range strings.Split(v, ",") {
			p, _, _ := strings.Cut(part, "=")
			if strings.EqualFold(strings.TrimSpace(p), token) {
				return true
			}
		}
	}
	return false
}

func parseContentLength(s string) (int64, error) {
	var n int64
	_, err := fmt.Sscan(strings.TrimSpace(s), &n)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("invalid Content-Length %q", s)
	}
	return n, nil
}

func normalizeTypes(types []string) []string {
	out := make([]string, 0, len(types))
	for _, t := range types {
		t = strings.ToLower(strings.TrimSpace(t))
		if t != "" {
			out = append(out, t)
		}
	}
	return out
}

func matchesAnyType(mediaType string, patterns []string) bool {
	for _, p := range patterns {
		if matchMediaType(p, mediaType) {
			return true
		}
	}
	return false
}

// matchMediaType matches "type/subtype" against a pattern: an exact type,
// "*/*", "type/*", "type/*+suffix" (structured syntax, RFC 6838 §4.2.8) or
// "type/prefix+*".
func matchMediaType(pattern, mediaType string) bool {
	if pattern == "*/*" || pattern == mediaType {
		return true
	}
	pType, pSub, ok := strings.Cut(pattern, "/")
	if !ok {
		return false
	}
	mType, mSub, ok := strings.Cut(mediaType, "/")
	if !ok || (pType != "*" && pType != mType) {
		return false
	}
	switch {
	case pSub == "*":
		return true
	case strings.HasPrefix(pSub, "*+"):
		return strings.HasSuffix(mSub, pSub[1:])
	case strings.HasSuffix(pSub, "+*"):
		return strings.HasPrefix(mSub, pSub[:len(pSub)-1])
	}
	return pSub == mSub
}
