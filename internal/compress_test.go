/*
 * Copyright 2024 Jonas Kaninda — Apache-2.0
 */

package internal

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jkaninda/goma-gateway/internal/middlewares"
	"github.com/klauspost/compress/gzip"
	"github.com/klauspost/compress/zstd"
	"gopkg.in/yaml.v3"
)

var compressBody = strings.Repeat(`{"id":42,"name":"goma","region":"eu-west-3","ok":true},`, 300)

// newCompressTestGateway builds a real router for one route proxying to
// backend, with the middlewares given as YAML.
func newCompressTestGateway(t *testing.T, backend string, middlewaresYAML string, routeMiddlewares ...string) *router {
	t.Helper()
	var mids []Middleware
	if err := yaml.Unmarshal([]byte(middlewaresYAML), &mids); err != nil {
		t.Fatal(err)
	}
	route := Route{
		Name:        "api",
		Path:        "/",
		Target:      backend,
		Enabled:     true,
		Middlewares: routeMiddlewares,
	}
	table := newProxyRouter(false)
	r := &router{}
	r.setTable(table)
	if err := r.addRoutesTo(table, []Route{route}, mids, nil); err != nil {
		t.Fatal(err)
	}
	return r
}

func gatewayGet(r http.Handler, accept string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "http://gateway.test/items", nil)
	if accept != "" {
		req.Header.Set("Accept-Encoding", accept)
	}
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

func gunzip(t *testing.T, b []byte) string {
	t.Helper()
	zr, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		t.Fatalf("gzip: %v", err)
	}
	out, err := io.ReadAll(zr)
	if err != nil {
		t.Fatalf("gzip: %v", err)
	}
	return string(out)
}

func unzstd(t *testing.T, b []byte) string {
	t.Helper()
	zr, err := zstd.NewReader(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	out, err := io.ReadAll(zr)
	if err != nil {
		t.Fatalf("zstd: %v", err)
	}
	return string(out)
}

func TestCompressRouteEndToEnd(t *testing.T) {
	var sawAE atomic.Value
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAE.Store(r.Header.Get("Accept-Encoding"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, compressBody)
	}))
	defer backend.Close()

	gw := newCompressTestGateway(t, backend.URL, `
- name: compression
  type: compress
  rule:
    algorithms: [zstd, gzip]
    minSize: 512
    levels: {gzip: 6, zstd: fastest}
    upstream: identity
`, "compression")

	rec := gatewayGet(gw, "gzip, deflate, br, zstd")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	if ce := rec.Header().Get("Content-Encoding"); ce != middlewares.EncodingZstd {
		t.Fatalf("Content-Encoding = %q", ce)
	}
	if got := unzstd(t, rec.Body.Bytes()); got != compressBody {
		t.Fatal("body mismatch through the gateway")
	}
	if got := rec.Header().Get("X-Goma-Compression"); got != middlewares.EncodingZstd {
		t.Fatalf("X-Goma-Compression = %q, want zstd", got)
	}
	if ae, _ := sawAE.Load().(string); ae != "identity" {
		t.Fatalf("backend saw Accept-Encoding %q, want identity", ae)
	}
	if rec.Header().Get("Proxied-By") == "" {
		t.Error("outer gateway headers missing")
	}

	rec = gatewayGet(gw, "")
	if rec.Header().Get("Content-Encoding") != "" || rec.Body.String() != compressBody {
		t.Fatal("identity client must get the plain body")
	}
	if rec.Header().Get("X-Goma-Compression") != "" {
		t.Fatal("X-Goma-Compression set on an uncompressed response")
	}
}

func TestCompressRuleAcceptsSizeForms(t *testing.T) {
	for _, minSize := range []string{"2048", `"2KiB"`, `"2 KiB"`} {
		var mids []Middleware
		doc := "- name: c\n  type: compress\n  rule:\n    minSize: " + minSize + "\n"
		if err := yaml.Unmarshal([]byte(doc), &mids); err != nil {
			t.Fatal(err)
		}
		r := &Route{Name: "x", Path: "/"}
		if err := applyCompressMiddleware(mids[0], r); err != nil {
			t.Fatalf("minSize %s: %v", minSize, err)
		}
		if r.compression == nil {
			t.Fatalf("minSize %s: no compressor", minSize)
		}
	}
}

func TestCompressRuleRejectsBadConfig(t *testing.T) {
	for _, rule := range []string{
		"algorithms: [lz4]",
		"minSize: lots",
		"upstream: sometimes",
		"levels: {gzip: 42}",
	} {
		var mids []Middleware
		doc := "- name: c\n  type: compress\n  rule:\n    " + rule + "\n"
		if err := yaml.Unmarshal([]byte(doc), &mids); err != nil {
			t.Fatal(err)
		}
		if err := applyCompressMiddleware(mids[0], &Route{Name: "x", Path: "/"}); err == nil {
			t.Errorf("rule %q accepted", rule)
		}
	}
}

// A misconfigured compress middleware fails closed like every other
// middleware: the route answers 503 rather than silently serving uncompressed.
func TestCompressMisconfiguredRouteFailsClosed(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer backend.Close()
	gw := newCompressTestGateway(t, backend.URL, `
- name: compression
  type: compress
  rule: {algorithms: [lz4]}
`, "compression")
	if rec := gatewayGet(gw, "gzip"); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status %d, want 503", rec.Code)
	}
}

// With httpCache listed before compress, the cache stores the compressed
// variant per accepted-codings set: the second identical request is a hit and
// never reaches the backend, and a gzip-only client gets its own entry.
func TestCompressWithHttpCache(t *testing.T) {
	var hits atomic.Int64
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=60")
		_, _ = io.WriteString(w, compressBody)
	}))
	defer backend.Close()

	// compress is listed first on purpose: placement must not depend on order.
	gw := newCompressTestGateway(t, backend.URL, `
- name: compression
  type: compress
- name: cache
  type: httpCache
  paths: ["/*"]
  rule:
    maxTtl: 60
`, "compression", "cache")

	first := gatewayGet(gw, "zstd, gzip")
	second := gatewayGet(gw, "gzip, zstd") // same set, other order
	if hits.Load() != 1 {
		t.Fatalf("backend hit %d times, want 1 (second request should be a cache hit)", hits.Load())
	}
	for i, rec := range []*httptest.ResponseRecorder{first, second} {
		if rec.Header().Get("Content-Encoding") != middlewares.EncodingZstd {
			t.Fatalf("response %d: Content-Encoding = %q", i, rec.Header().Get("Content-Encoding"))
		}
		if unzstd(t, rec.Body.Bytes()) != compressBody {
			t.Fatalf("response %d: body mismatch", i)
		}
	}

	gz := gatewayGet(gw, "gzip")
	if hits.Load() != 2 {
		t.Fatalf("gzip-only client must not share the zstd entry (backend hits %d)", hits.Load())
	}
	if gz.Header().Get("Content-Encoding") != middlewares.EncodingGzip || gunzip(t, gz.Body.Bytes()) != compressBody {
		t.Fatal("gzip client got the wrong coding")
	}
	plain := gatewayGet(gw, "")
	if plain.Header().Get("Content-Encoding") != "" || plain.Body.String() != compressBody {
		t.Fatal("identity client got an encoded body")
	}
}

// The error interceptor replaces the upstream body; the upstream's coding
// header must not survive over the gateway's plain error page.
func TestErrorInterceptorDropsUpstreamEncoding(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		_, _ = io.WriteString(zw, "upstream exploded")
		_ = zw.Close()
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("ETag", `"boom"`)
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write(buf.Bytes())
	}))
	defer backend.Close()

	gw := newCompressTestGateway(t, backend.URL, `
- name: errors
  type: errorInterceptor
  rule:
    enabled: true
    contentType: application/json
    errors:
      - statusCode: 502
        body: '{"error":"bad gateway"}'
`, "errors")

	rec := gatewayGet(gw, "gzip")
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status %d", rec.Code)
	}
	if ce := rec.Header().Get("Content-Encoding"); ce != "" {
		t.Fatalf("Content-Encoding %q left over a plain error body %q", ce, rec.Body.String())
	}
	if rec.Header().Get("ETag") != "" {
		t.Error("upstream ETag left on the replaced body")
	}
	if !strings.Contains(rec.Body.String(), "bad gateway") {
		t.Fatalf("body = %q", rec.Body.String())
	}
}

// Chunked streams must reach the client as they are flushed, through the
// gateway's response wrapper, with and without compression.
func TestGatewayStreamsFlushedChunks(t *testing.T) {
	for _, withCompress := range []bool{false, true} {
		name := "plain"
		if withCompress {
			name = "compressed"
		}
		t.Run(name, func(t *testing.T) {
			release := make(chan struct{})
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/x-ndjson")
				_, _ = io.WriteString(w, `{"n":1}`+"\n")
				w.(http.Flusher).Flush()
				<-release
				_, _ = io.WriteString(w, `{"n":2}`+"\n")
			}))

			mids, names := "[]", []string(nil)
			if withCompress {
				mids, names = "- name: c\n  type: compress\n", []string{"c"}
			}
			gw := newCompressTestGateway(t, backend.URL, mids, names...)
			front := httptest.NewServer(gw)
			// LIFO: release the backend first, or closing the servers waits
			// on a handler that is itself waiting on release.
			defer front.Close()
			defer backend.Close()
			defer close(release)

			// The client decodes gzip transparently. The timeout bounds the wait
			// for headers too: an unflushed gateway sends nothing at all.
			client := &http.Client{Timeout: 3 * time.Second}
			resp, err := client.Get(front.URL + "/stream")
			if err != nil {
				t.Fatalf("no response while the backend is mid-stream: %v", err)
			}
			defer resp.Body.Close()
			got := make(chan string, 1)
			go func() {
				buf := make([]byte, 64)
				n, _ := io.ReadAtLeast(resp.Body, buf, len(`{"n":1}`+"\n"))
				got <- string(buf[:n])
			}()
			select {
			case s := <-got:
				if s != `{"n":1}`+"\n" {
					t.Fatalf("first chunk = %q", s)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("first chunk held back by the gateway")
			}
		})
	}
}

func TestStreamDetection(t *testing.T) {
	sse := httptest.NewRequest(http.MethodGet, "/", nil)
	sse.Header.Set("Accept", "text/event-stream, */*;q=0.1")
	if !isSSE(sse) {
		t.Error("SSE with extra media types not detected")
	}
	ws := httptest.NewRequest(http.MethodGet, "/", nil)
	ws.Header.Set("Upgrade", "WebSocket")
	if !isWebSocketRequest(ws) {
		t.Error("mixed-case WebSocket upgrade not detected")
	}
	plain := httptest.NewRequest(http.MethodGet, "/", nil)
	plain.Header.Set("Accept", "application/json")
	if isSSE(plain) || isWebSocketRequest(plain) {
		t.Error("plain request detected as a stream")
	}
}

// The client sends back the weakened ETag; the backend only knows the strong one.
func TestCompressKeepsRevalidationWorking(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") == `"v1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"v1"`)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, compressBody)
	}))
	defer backend.Close()
	gw := newCompressTestGateway(t, backend.URL, "- name: c\n  type: compress\n", "c")

	etag := gatewayGet(gw, "gzip").Header().Get("ETag")
	if etag != `W/"v1"` {
		t.Fatalf("ETag = %q, want W/\"v1\"", etag)
	}
	req := httptest.NewRequest(http.MethodGet, "http://gateway.test/items", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	req.Header.Set("If-None-Match", etag)
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotModified {
		t.Fatalf("revalidation status %d, want 304", rec.Code)
	}
}

// Every built-in type is checked against this list on load; a missing one logs "Middleware type not found".
func TestCompressIsBuiltIn(t *testing.T) {
	for _, mt := range []MiddlewareType{compress, geoBlock} {
		if !doesExist(string(mt)) {
			t.Errorf("%s is not in buildInMiddlewares", mt)
		}
	}
}
