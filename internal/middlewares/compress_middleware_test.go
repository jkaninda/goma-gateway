/*
 * Copyright 2024 Jonas Kaninda — Apache-2.0
 */

package middlewares

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/gzip"
	"github.com/klauspost/compress/zstd"
)

var jsonBody = strings.Repeat(`{"id":12345,"name":"goma gateway","tags":["api","edge","proxy"],"active":true},`, 200)

func newTestCompressor(t testing.TB, cfg CompressConfig) *Compressor {
	t.Helper()
	c, err := NewCompressor(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func decode(t testing.TB, encoding string, body []byte) []byte {
	t.Helper()
	var r io.Reader
	switch encoding {
	case "", EncodingIdentity:
		return body
	case EncodingGzip:
		zr, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			t.Fatalf("gzip reader: %v", err)
		}
		r = zr
	case EncodingZstd:
		zr, err := zstd.NewReader(bytes.NewReader(body))
		if err != nil {
			t.Fatalf("zstd reader: %v", err)
		}
		defer zr.Close()
		r = zr
	case EncodingBrotli:
		r = brotli.NewReader(bytes.NewReader(body))
	default:
		t.Fatalf("unexpected encoding %q", encoding)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("decode %s: %v", encoding, err)
	}
	return out
}

func compressServe(c *Compressor, h http.HandlerFunc, req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	c.Middleware(h).ServeHTTP(rec, req)
	return rec
}

func jsonHandler(body string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("ETag", `"v1"`)
		w.Header().Set("Accept-Ranges", "bytes")
		_, _ = io.WriteString(w, body)
	}
}

func compressGet(accept string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/api/items", nil)
	if accept != "" {
		r.Header.Set("Accept-Encoding", accept)
	}
	return r
}

func TestCompressEachAlgorithm(t *testing.T) {
	c := newTestCompressor(t, CompressConfig{})
	for _, enc := range []string{EncodingZstd, EncodingBrotli, EncodingGzip} {
		t.Run(enc, func(t *testing.T) {
			rec := compressServe(c, jsonHandler(jsonBody), compressGet(enc))
			if got := rec.Header().Get("Content-Encoding"); got != enc {
				t.Fatalf("Content-Encoding = %q, want %q", got, enc)
			}
			if got := decode(t, enc, rec.Body.Bytes()); string(got) != jsonBody {
				t.Fatalf("round trip mismatch: %d bytes vs %d", len(got), len(jsonBody))
			}
			if rec.Body.Len() >= len(jsonBody)/4 {
				t.Errorf("poor ratio: %d -> %d", len(jsonBody), rec.Body.Len())
			}
			h := rec.Header()
			if h.Get("Vary") != "Accept-Encoding" {
				t.Errorf("Vary = %q", h.Get("Vary"))
			}
			if h.Get("ETag") != `W/"v1"` {
				t.Errorf("ETag not weakened: %q", h.Get("ETag"))
			}
			if h.Get("Accept-Ranges") != "" || h.Get("Content-Length") != "" {
				t.Errorf("stale headers left: Accept-Ranges=%q Content-Length=%q", h.Get("Accept-Ranges"), h.Get("Content-Length"))
			}
		})
	}
}

func TestCompressSkips(t *testing.T) {
	c := newTestCompressor(t, CompressConfig{ExcludedPaths: []string{"/login"}})
	big := jsonBody

	cases := []struct {
		name    string
		req     func() *http.Request
		handler http.HandlerFunc
		vary    bool // expect Vary: Accept-Encoding even though not compressed
	}{
		{
			name: "identity client", req: func() *http.Request { return compressGet("") },
			handler: jsonHandler(big), vary: true,
		},
		{
			name: "small body", req: func() *http.Request { return compressGet("gzip") },
			handler: jsonHandler(`{"ok":true}`), vary: true,
		},
		{
			name: "small body with Content-Length", req: func() *http.Request { return compressGet("gzip") },
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "text/html")
				w.Header().Set("Content-Length", "11")
				_, _ = io.WriteString(w, "hello world")
			},
			vary: true,
		},
		{
			name: "image", req: func() *http.Request { return compressGet("gzip") },
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "image/png")
				_, _ = io.WriteString(w, big)
			},
		},
		{
			name: "already encoded", req: func() *http.Request { return compressGet("gzip, br") },
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Content-Encoding", "br")
				_, _ = io.WriteString(w, big)
			},
			vary: true,
		},
		{
			name: "no-transform", req: func() *http.Request { return compressGet("gzip") },
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Cache-Control", "public, no-transform")
				_, _ = io.WriteString(w, big)
			},
			vary: true,
		},
		{
			name: "range request", req: func() *http.Request { r := compressGet("gzip"); r.Header.Set("Range", "bytes=0-99"); return r },
			handler: jsonHandler(big), vary: true,
		},
		{
			name: "partial content", req: func() *http.Request { return compressGet("gzip") },
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Content-Range", "bytes 0-99/5000")
				w.WriteHeader(http.StatusPartialContent)
				_, _ = io.WriteString(w, big[:100])
			},
			vary: true,
		},
		{
			name: "HEAD", req: func() *http.Request { r := compressGet("gzip"); r.Method = http.MethodHead; return r },
			handler: jsonHandler(big), vary: true,
		},
		{
			name: "SSE", req: func() *http.Request { return compressGet("gzip") },
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "text/event-stream")
				_, _ = io.WriteString(w, big)
			},
		},
		{
			name: "gRPC", req: func() *http.Request { return compressGet("gzip") },
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/grpc+proto")
				_, _ = io.WriteString(w, big)
			},
		},
		{
			name: "excluded path", req: func() *http.Request {
				r := httptest.NewRequest(http.MethodGet, "/login", nil)
				r.Header.Set("Accept-Encoding", "gzip")
				return r
			},
			handler: jsonHandler(big),
		},
		{
			name: "websocket upgrade", req: func() *http.Request {
				r := compressGet("gzip")
				r.Header.Set("Connection", "Upgrade")
				r.Header.Set("Upgrade", "websocket")
				return r
			},
			handler: jsonHandler(big),
		},
		{
			name: "no content type", req: func() *http.Request { return compressGet("gzip") },
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = io.WriteString(w, big)
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var want bytes.Buffer
			ref := httptest.NewRecorder()
			tc.handler(ref, tc.req())
			want.Write(ref.Body.Bytes())

			rec := compressServe(c, tc.handler, tc.req())
			if ce := rec.Header().Get("Content-Encoding"); ce != ref.Header().Get("Content-Encoding") {
				t.Fatalf("Content-Encoding changed to %q", ce)
			}
			if !bytes.Equal(rec.Body.Bytes(), want.Bytes()) {
				t.Fatalf("body changed: %d bytes, want %d", rec.Body.Len(), want.Len())
			}
			gotVary := strings.Contains(rec.Header().Get("Vary"), "Accept-Encoding")
			if gotVary != tc.vary {
				t.Errorf("Vary: Accept-Encoding present=%v, want %v", gotVary, tc.vary)
			}
			if rec.Code != ref.Code {
				t.Errorf("status %d, want %d", rec.Code, ref.Code)
			}
		})
	}
}

func TestCompressStatusesWithoutBody(t *testing.T) {
	c := newTestCompressor(t, CompressConfig{})
	for _, code := range []int{http.StatusNoContent, http.StatusNotModified} {
		rec := compressServe(c, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(code)
		}, compressGet("gzip"))
		if rec.Code != code || rec.Header().Get("Content-Encoding") != "" || rec.Body.Len() != 0 {
			t.Errorf("%d: code=%d ce=%q body=%d", code, rec.Code, rec.Header().Get("Content-Encoding"), rec.Body.Len())
		}
	}
}

func TestCompressKeepsExistingVary(t *testing.T) {
	c := newTestCompressor(t, CompressConfig{})
	rec := compressServe(c, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Vary", "Origin")
		_, _ = io.WriteString(w, jsonBody)
	}, compressGet("gzip"))
	if got := rec.Header().Values("Vary"); len(got) != 2 || got[0] != "Origin" || got[1] != "Accept-Encoding" {
		t.Fatalf("Vary = %v", got)
	}
	rec = compressServe(c, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Vary", "accept-encoding")
		_, _ = io.WriteString(w, jsonBody)
	}, compressGet("gzip"))
	if got := rec.Header().Values("Vary"); len(got) != 1 {
		t.Fatalf("Vary duplicated: %v", got)
	}
}

// A body written in many small pieces, with no Content-Length, crosses the
// threshold part way and must still round-trip exactly.
func TestCompressManySmallWrites(t *testing.T) {
	c := newTestCompressor(t, CompressConfig{MinSize: 512})
	rec := compressServe(c, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		for i := 0; i < 400; i++ {
			_, _ = fmt.Fprintf(w, "line %04d\n", i)
		}
	}, compressGet("zstd"))
	if rec.Header().Get("Content-Encoding") != EncodingZstd {
		t.Fatalf("not compressed")
	}
	var want strings.Builder
	for i := 0; i < 400; i++ {
		fmt.Fprintf(&want, "line %04d\n", i)
	}
	if got := decode(t, EncodingZstd, rec.Body.Bytes()); string(got) != want.String() {
		t.Fatal("round trip mismatch")
	}
}

func TestCompressSniffsMissingTypeOnImplicitWrite(t *testing.T) {
	c := newTestCompressor(t, CompressConfig{})
	rec := compressServe(c, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "<!DOCTYPE html><html><body>"+jsonBody+"</body></html>")
	}, compressGet("gzip"))
	if rec.Header().Get("Content-Encoding") != EncodingGzip {
		t.Fatalf("html without explicit type should be sniffed and compressed, got headers %v", rec.Header())
	}
}

func TestCompressUpstreamIdentity(t *testing.T) {
	c := newTestCompressor(t, CompressConfig{UpstreamIdentity: true})
	var seen string
	rec := compressServe(c, func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Get("Accept-Encoding")
		jsonHandler(jsonBody)(w, r)
	}, compressGet("gzip, br"))
	if seen != EncodingIdentity {
		t.Fatalf("upstream saw Accept-Encoding %q, want identity", seen)
	}
	if rec.Header().Get("Content-Encoding") != EncodingBrotli {
		t.Fatalf("gateway should still compress for the client")
	}
}

func TestCompressPathsScope(t *testing.T) {
	c := newTestCompressor(t, CompressConfig{RoutePath: "/", Paths: []string{"/api/*"}})
	rec := compressServe(c, jsonHandler(jsonBody), compressGet("gzip"))
	if rec.Header().Get("Content-Encoding") != EncodingGzip {
		t.Fatal("in-scope path not compressed")
	}
	r := httptest.NewRequest(http.MethodGet, "/static/app.json", nil)
	r.Header.Set("Accept-Encoding", "gzip")
	rec = compressServe(c, jsonHandler(jsonBody), r)
	if rec.Header().Get("Content-Encoding") != "" {
		t.Fatal("out-of-scope path compressed")
	}
}

func TestCompressConfigValidation(t *testing.T) {
	bad := []CompressConfig{
		{Algorithms: []string{"lz4"}},
		{GzipLevel: 12},
		{BrotliLevel: 12},
		{ZstdLevel: "turbo"},
		{MinSize: -1},
	}
	for _, cfg := range bad {
		if _, err := NewCompressor(cfg); err == nil {
			t.Errorf("config %+v accepted", cfg)
		}
	}
	c := newTestCompressor(t, CompressConfig{Algorithms: []string{"GZIP", "brotli", "gzip"}})
	if got := c.Algorithms(); len(got) != 2 || got[0] != EncodingGzip || got[1] != EncodingBrotli {
		t.Fatalf("algorithms normalised to %v", got)
	}
}

func TestCompressMetricsHooks(t *testing.T) {
	var in, out atomic.Int64
	var skips sync.Map
	c := newTestCompressor(t, CompressConfig{
		OnCompressed: func(_ string, i, o int64) { in.Add(i); out.Add(o) },
		OnSkipped:    func(reason string) { skips.Store(reason, true) },
	})
	rec := compressServe(c, jsonHandler(jsonBody), compressGet("gzip"))
	if in.Load() != int64(len(jsonBody)) || out.Load() != int64(rec.Body.Len()) {
		t.Fatalf("hook counted in=%d out=%d, want %d/%d", in.Load(), out.Load(), len(jsonBody), rec.Body.Len())
	}
	compressServe(c, jsonHandler("tiny"), compressGet("gzip"))
	if _, ok := skips.Load(SkipReasonSize); !ok {
		t.Fatal("size skip not reported")
	}
}

// Streaming: each flush must deliver a decodable chunk to the client before
// the handler finishes, through a real server and HTTP client.
func TestCompressStreamingFlush(t *testing.T) {
	for _, enc := range []string{EncodingGzip, EncodingZstd, EncodingBrotli} {
		t.Run(enc, func(t *testing.T) {
			c := newTestCompressor(t, CompressConfig{})
			release := make(chan struct{})
			srv := httptest.NewServer(c.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/x-ndjson")
				_, _ = io.WriteString(w, `{"event":1}`+"\n")
				w.(http.Flusher).Flush()
				<-release
				_, _ = io.WriteString(w, `{"event":2}`+"\n")
			})))
			defer srv.Close()

			req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
			req.Header.Set("Accept-Encoding", enc) // set explicitly: the client then does not auto-decode
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = resp.Body.Close() }()
			if resp.Header.Get("Content-Encoding") != enc {
				t.Fatalf("Content-Encoding = %q", resp.Header.Get("Content-Encoding"))
			}
			var dec io.Reader
			switch enc {
			case EncodingGzip:
				dec, err = gzip.NewReader(resp.Body)
			case EncodingZstd:
				var zr *zstd.Decoder
				zr, err = zstd.NewReader(resp.Body)
				dec = zr
			case EncodingBrotli:
				dec = brotli.NewReader(resp.Body)
			}
			if err != nil {
				t.Fatal(err)
			}
			lines := bufio.NewReader(dec)
			first := make(chan string, 1)
			go func() { l, _ := lines.ReadString('\n'); first <- l }()
			select {
			case l := <-first:
				if l != `{"event":1}`+"\n" {
					t.Fatalf("first event = %q", l)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("first event was not flushed to the client")
			}
			close(release)
			rest, _ := io.ReadAll(lines)
			if string(rest) != `{"event":2}`+"\n" {
				t.Fatalf("second event = %q", rest)
			}
		})
	}
}

// Encoders are pooled: concurrent responses must never share one.
func TestCompressConcurrent(t *testing.T) {
	c := newTestCompressor(t, CompressConfig{})
	var wg sync.WaitGroup
	for i := 0; i < 200; i++ {
		enc := []string{EncodingGzip, EncodingZstd, EncodingBrotli}[i%3]
		body := fmt.Sprintf("%d:%s", i, jsonBody)
		wg.Go(func() {
			rec := compressServe(c, jsonHandler(body), compressGet(enc))
			if got := decode(t, enc, rec.Body.Bytes()); string(got) != body {
				t.Errorf("request %s mismatch", enc)
			}
		})
	}
	wg.Wait()
}

func TestMatchMediaType(t *testing.T) {
	cases := []struct {
		pattern, mediaType string
		want               bool
	}{
		{"text/*", "text/html", true},
		{"application/*+json", "application/problem+json", true},
		{"application/*+json", "application/json", false},
		{"application/grpc+*", "application/grpc+proto", true},
		{"application/json", "application/json", true},
		{"application/json", "application/jsonx", false},
		{"*/*", "image/png", true},
		{"image/*", "text/plain", false},
	}
	for _, tc := range cases {
		if got := matchMediaType(tc.pattern, tc.mediaType); got != tc.want {
			t.Errorf("matchMediaType(%q, %q) = %v", tc.pattern, tc.mediaType, got)
		}
	}
}

func TestStrengthenIfNoneMatch(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{`W/"a"`, `"a"`},
		{`W/"a", "b",W/"c"`, `"a", "b", "c"`},
		{`"a"`, `"a"`},
		{`*`, `*`},
	} {
		h := http.Header{}
		h.Set("If-None-Match", tc.in)
		strengthenIfNoneMatch(h)
		if got := h.Get("If-None-Match"); got != tc.want {
			t.Errorf("strengthenIfNoneMatch(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
