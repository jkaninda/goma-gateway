/*
 * Copyright 2024 Jonas Kaninda — Apache-2.0
 */

package internal

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// The pool must hand out buffers of ReverseProxy's own default size, and must
// not let a foreign, smaller buffer in.
func TestProxyBufferPoolSizes(t *testing.T) {
	p := newProxyBufferPool()

	b := p.Get()
	if len(b) != proxyBufferSize {
		t.Fatalf("Get returned %d bytes, want %d", len(b), proxyBufferSize)
	}
	p.Put(b[:10])
	if got := p.Get(); len(got) != proxyBufferSize {
		t.Fatalf("Get after Put of a resliced buffer returned %d bytes, want %d", len(got), proxyBufferSize)
	}

	p.Put(make([]byte, 1024))
	for i := 0; i < 8; i++ {
		if got := p.Get(); len(got) != proxyBufferSize {
			t.Fatalf("pool returned a %d-byte buffer it should have rejected", len(got))
		}
	}
}

// Every reverse proxy the gateway builds must use the shared pool.
func TestNewReverseProxyUsesPool(t *testing.T) {
	target, _ := url.Parse("http://127.0.0.1:9")
	if rp := newReverseProxy(target); rp.BufferPool != responseBufferPool {
		t.Fatal("newReverseProxy did not attach responseBufferPool")
	}
}

// Run with -benchmem: the pooled variant should allocate roughly 32 KiB less
// per request than the default.
func BenchmarkReverseProxyBuffers(b *testing.B) {
	body := strings.Repeat("x", 100)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, body)
	}))
	defer backend.Close()
	target, _ := url.Parse(backend.URL)

	run := func(b *testing.B, pooled bool) {
		rp := newReverseProxy(target)
		if !pooled {
			rp.BufferPool = nil
		}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			rec := httptest.NewRecorder()
			rp.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
			if rec.Code != http.StatusOK {
				b.Fatalf("status %d", rec.Code)
			}
		}
	}
	b.Run("default", func(b *testing.B) { run(b, false) })
	b.Run("pooled", func(b *testing.B) { run(b, true) })
}
