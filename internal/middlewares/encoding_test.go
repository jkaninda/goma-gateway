/*
 * Copyright 2024 Jonas Kaninda — Apache-2.0
 */

package middlewares

import (
	"net/http/httptest"
	"testing"
)

func TestNegotiateEncoding(t *testing.T) {
	pref := []string{EncodingZstd, EncodingBrotli, EncodingGzip}
	cases := []struct {
		name, header string
		absent       bool
		want         string
	}{
		{name: "no header", absent: true, want: EncodingIdentity},
		{name: "empty header", header: "", want: EncodingIdentity},
		{name: "browser", header: "gzip, deflate, br, zstd", want: EncodingZstd},
		{name: "server preference breaks ties", header: "gzip, br", want: EncodingBrotli},
		{name: "q-value beats preference", header: "zstd;q=0.5, gzip", want: EncodingGzip},
		{name: "q=0 refuses", header: "gzip;q=0, br", want: EncodingBrotli},
		{name: "only refused", header: "gzip;q=0", want: EncodingIdentity},
		{name: "star", header: "*", want: EncodingZstd},
		{name: "star with exclusion", header: "*;q=0.1, zstd;q=0", want: EncodingBrotli},
		{name: "star zero", header: "*;q=0", want: EncodingIdentity},
		{name: "case and spaces", header: "  GZIP ;  Q=0.8 ,BR;q=0.9 ", want: EncodingBrotli},
		{name: "x-gzip alias", header: "x-gzip", want: EncodingGzip},
		{name: "unknown only", header: "compress, deflate", want: EncodingIdentity},
		{name: "malformed q is dropped", header: "br;q=abc, gzip", want: EncodingGzip},
		{name: "q out of range is dropped", header: "br;q=2, gzip", want: EncodingGzip},
		{name: "identity only", header: "identity", want: EncodingIdentity},
		{name: "duplicate keeps highest", header: "gzip;q=0, gzip;q=1", want: EncodingGzip},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/", nil)
			if !tc.absent {
				r.Header["Accept-Encoding"] = []string{tc.header}
			}
			if got := NegotiateEncoding(r, pref); got != tc.want {
				t.Fatalf("NegotiateEncoding(%q) = %q, want %q", tc.header, got, tc.want)
			}
		})
	}
}

func TestAcceptedCodingsKey(t *testing.T) {
	cases := map[string]string{
		"gzip, deflate, br, zstd": "br+deflate+gzip+zstd",
		"zstd, br, deflate, gzip": "br+deflate+gzip+zstd", // permutation collapses
		"br;q=0, gzip":            "gzip",                 // q=0 is not accepted
		"gzip;q=0.1":              "gzip",                 // any q>0 is the same entry
		"identity":                "identity",
		"*":                       "br+deflate+gzip+zstd",
		"":                        "identity",
	}
	for header, want := range cases {
		r := httptest.NewRequest("GET", "/", nil)
		r.Header.Set("Accept-Encoding", header)
		if got := AcceptedCodingsKey(r); got != want {
			t.Errorf("AcceptedCodingsKey(%q) = %q, want %q", header, got, want)
		}
	}
	r := httptest.NewRequest("GET", "/", nil)
	if got := AcceptedCodingsKey(r); got != EncodingIdentity {
		t.Errorf("no header: got %q", got)
	}
}

func TestAcceptsEncoding(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Accept-Encoding", "gzip, identity;q=0")
	if AcceptsEncoding(r, EncodingIdentity) {
		t.Error("identity;q=0 should refuse identity")
	}
	if !AcceptsEncoding(r, EncodingGzip) {
		t.Error("gzip should be accepted")
	}
	r.Header.Set("Accept-Encoding", "*;q=0")
	if AcceptsEncoding(r, EncodingIdentity) {
		t.Error("*;q=0 without identity refuses identity")
	}
	r.Header.Set("Accept-Encoding", "br")
	if !AcceptsEncoding(r, EncodingIdentity) {
		t.Error("identity is acceptable unless refused")
	}
}

func FuzzNegotiateEncoding(f *testing.F) {
	for _, seed := range []string{"gzip", "br;q=0.5, *;q=0", "zstd;q=1.0,gzip;q=", ";;,,q=", "x-gzip;q=0.001"} {
		f.Add(seed)
	}
	pref := []string{EncodingZstd, EncodingBrotli, EncodingGzip}
	f.Fuzz(func(t *testing.T, header string) {
		r := httptest.NewRequest("GET", "/", nil)
		r.Header.Set("Accept-Encoding", header)
		got := NegotiateEncoding(r, pref)
		if got != EncodingIdentity && !AcceptsEncoding(r, got) {
			t.Fatalf("negotiated %q which the client does not accept (%q)", got, header)
		}
		_ = AcceptedCodingsKey(r)
	})
}
