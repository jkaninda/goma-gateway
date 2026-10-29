/*
 * Copyright 2024 Jonas Kaninda — Apache-2.0
 */

package middlewares

import (
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// benchFixtures builds realistic JSON and HTML bodies of the given size:
// repetitive in structure but not in values, like real API and page output.
func benchFixture(kind string, size int) []byte {
	rng := rand.New(rand.NewSource(42))
	var b strings.Builder
	switch kind {
	case "json":
		b.WriteString("[")
		for i := 0; b.Len() < size; i++ {
			fmt.Fprintf(&b, `{"id":%d,"sku":"SKU-%06d","name":"Item %d","price":%.2f,"stock":%d,"tags":["edge","api"],"active":%t,"region":"eu-west-3"},`,
				i, rng.Intn(1_000_000), i, rng.Float64()*500, rng.Intn(1000), i%2 == 0)
		}
	case "html":
		b.WriteString("<!doctype html><html><head><title>Goma</title></head><body>")
		for i := 0; b.Len() < size; i++ {
			fmt.Fprintf(&b, `<div class="card" id="c%d"><h2>Product %d</h2><p>Price %.2f EUR. Ships from Kinshasa in %d days.</p><a href="/p/%d">View</a></div>`,
				i, i, rng.Float64()*500, 1+rng.Intn(9), rng.Intn(100000))
		}
	}
	out := []byte(b.String())
	if len(out) > size {
		out = out[:size]
	}
	return out
}

type discardWriter struct {
	h http.Header
	n int64
}

func (d *discardWriter) Header() http.Header         { return d.h }
func (d *discardWriter) WriteHeader(int)             {}
func (d *discardWriter) Write(p []byte) (int, error) { d.n += int64(len(p)); return len(p), nil }

// BenchmarkCompress measures the middleware alone: negotiation, the writer,
// a pooled encoder and the encode itself. MB/s is input throughput; ratio is
// output/input.
//
//	go test ./internal/middlewares -run '^$' -bench BenchmarkCompress -benchmem
func BenchmarkCompress(b *testing.B) {
	sizes := []struct {
		name string
		n    int
	}{{"1KiB", 1 << 10}, {"16KiB", 16 << 10}, {"64KiB", 64 << 10}, {"1MiB", 1 << 20}}

	for _, kind := range []string{"json", "html"} {
		for _, size := range sizes {
			body := benchFixture(kind, size.n)
			ct := map[string]string{"json": "application/json", "html": "text/html; charset=utf-8"}[kind]
			for _, enc := range []string{EncodingIdentity, EncodingGzip, EncodingZstd, EncodingBrotli} {
				b.Run(fmt.Sprintf("%s/%s/%s", kind, size.name, enc), func(b *testing.B) {
					c, err := NewCompressor(CompressConfig{MinSize: 512})
					if err != nil {
						b.Fatal(err)
					}
					h := c.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
						w.Header().Set("Content-Type", ct)
						// ReverseProxy copies in 32 KiB chunks; mirror that.
						for off := 0; off < len(body); off += 32 << 10 {
							end := min(off+32<<10, len(body))
							_, _ = w.Write(body[off:end])
						}
					}))
					req := httptest.NewRequest(http.MethodGet, "/", nil)
					if enc != EncodingIdentity {
						req.Header.Set("Accept-Encoding", enc)
					}
					w := &discardWriter{h: make(http.Header, 8)}
					b.SetBytes(int64(len(body)))
					b.ReportAllocs()
					b.ResetTimer()
					var out int64
					for i := 0; i < b.N; i++ {
						clear(w.h)
						w.n = 0
						h.ServeHTTP(w, req)
						out = w.n
					}
					b.ReportMetric(float64(out)/float64(len(body)), "ratio")
				})
			}
		}
	}
}

// BenchmarkCompressLevels compares levels on 64 KiB JSON and HTML bodies.
func BenchmarkCompressLevels(b *testing.B) {
	cases := []struct {
		name string
		enc  string
		cfg  CompressConfig
	}{
		{"gzip-1", EncodingGzip, CompressConfig{GzipLevel: 1}},
		{"gzip-5", EncodingGzip, CompressConfig{GzipLevel: 5}},
		{"gzip-9", EncodingGzip, CompressConfig{GzipLevel: 9}},
		{"zstd-fastest", EncodingZstd, CompressConfig{ZstdLevel: "fastest"}},
		{"zstd-default", EncodingZstd, CompressConfig{ZstdLevel: "default"}},
		{"zstd-better", EncodingZstd, CompressConfig{ZstdLevel: "better"}},
		{"br-1", EncodingBrotli, CompressConfig{BrotliLevel: 1}},
		{"br-2", EncodingBrotli, CompressConfig{BrotliLevel: 2}},
		{"br-4", EncodingBrotli, CompressConfig{BrotliLevel: 4}},
		{"br-6", EncodingBrotli, CompressConfig{BrotliLevel: 6}},
	}
	for _, kind := range []string{"json", "html"} {
		body := benchFixture(kind, 64<<10)
		for _, tc := range cases {
			b.Run(kind+"/"+tc.name, func(b *testing.B) {
				c, err := NewCompressor(tc.cfg)
				if err != nil {
					b.Fatal(err)
				}
				h := c.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.Header().Set("Content-Type", "text/html")
					_, _ = w.Write(body)
				}))
				req := httptest.NewRequest(http.MethodGet, "/", nil)
				req.Header.Set("Accept-Encoding", tc.enc)
				w := &discardWriter{h: make(http.Header, 8)}
				b.SetBytes(int64(len(body)))
				b.ReportAllocs()
				b.ResetTimer()
				var out int64
				for i := 0; i < b.N; i++ {
					clear(w.h)
					w.n = 0
					h.ServeHTTP(w, req)
					out = w.n
				}
				b.ReportMetric(float64(out)/float64(len(body)), "ratio")
			})
		}
	}
}

func BenchmarkNegotiateEncoding(b *testing.B) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept-Encoding", "gzip, deflate, br, zstd")
	pref := []string{EncodingZstd, EncodingBrotli, EncodingGzip}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = NegotiateEncoding(req, pref)
	}
}

// BenchmarkCompressFile runs the level comparison on a file of your own, for
// tuning against real payloads:
//
//	GOMA_BENCH_FILE=/path/to/response.json go test ./internal/middlewares \
//	  -run '^$' -bench BenchmarkCompressFile -benchmem
func BenchmarkCompressFile(b *testing.B) {
	path := os.Getenv("GOMA_BENCH_FILE")
	if path == "" {
		b.Skip("set GOMA_BENCH_FILE to a response body to benchmark")
	}
	body, err := os.ReadFile(path)
	if err != nil {
		b.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		enc  string
		cfg  CompressConfig
	}{
		{"gzip-1", EncodingGzip, CompressConfig{GzipLevel: 1}},
		{"gzip-5", EncodingGzip, CompressConfig{GzipLevel: 5}},
		{"zstd-fastest", EncodingZstd, CompressConfig{ZstdLevel: "fastest"}},
		{"zstd-default", EncodingZstd, CompressConfig{ZstdLevel: "default"}},
		{"br-1", EncodingBrotli, CompressConfig{BrotliLevel: 1}},
		{"br-4", EncodingBrotli, CompressConfig{BrotliLevel: 4}},
	} {
		b.Run(tc.name, func(b *testing.B) {
			c, err := NewCompressor(tc.cfg)
			if err != nil {
				b.Fatal(err)
			}
			h := c.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "text/plain")
				_, _ = w.Write(body)
			}))
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set("Accept-Encoding", tc.enc)
			w := &discardWriter{h: make(http.Header, 8)}
			b.SetBytes(int64(len(body)))
			b.ReportAllocs()
			var out int64
			for i := 0; i < b.N; i++ {
				clear(w.h)
				w.n = 0
				h.ServeHTTP(w, req)
				out = w.n
			}
			b.ReportMetric(float64(out)/float64(len(body)), "ratio")
		})
	}
}
