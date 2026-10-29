package middlewares

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRedirectHost(t *testing.T) {
	cases := []struct {
		name     string
		rh       RedirectHost
		url      string
		tls      bool
		wantCode int
		wantLoc  string
	}{
		{"add www", RedirectHost{WWW: WWWAdd, Permanent: true}, "http://example.com/a/b?x=1", true,
			http.StatusMovedPermanently, "https://www.example.com/a/b?x=1"},
		{"add www keeps plain http", RedirectHost{WWW: WWWAdd}, "http://example.com/", false,
			http.StatusFound, "http://www.example.com/"},
		{"add www already www", RedirectHost{WWW: WWWAdd}, "http://www.example.com/", true, http.StatusOK, ""},
		{"remove www", RedirectHost{WWW: WWWRemove}, "http://www.example.com/p", true,
			http.StatusFound, "https://example.com/p"},
		{"remove www keeps port", RedirectHost{WWW: WWWRemove}, "http://www.example.com:8443/p", true,
			http.StatusFound, "https://example.com:8443/p"},
		{"remove www on apex", RedirectHost{WWW: WWWRemove}, "http://example.com/", true, http.StatusOK, ""},
		{"fixed host", RedirectHost{Host: "example.com", Permanent: true}, "http://old.example.net/x", true,
			http.StatusMovedPermanently, "https://example.com/x"},
		{"fixed host already there", RedirectHost{Host: "Example.com"}, "http://example.com/x", true, http.StatusOK, ""},
		{"ip address", RedirectHost{WWW: WWWAdd}, "http://10.0.0.1/", true, http.StatusOK, ""},
		{"acme challenge", RedirectHost{WWW: WWWAdd}, "http://example.com/.well-known/acme-challenge/t", false, http.StatusOK, ""},
		{"host the route serves", RedirectHost{WWW: WWWAdd, Hosts: []string{"example.com", "www.example.com"}},
			"http://EXAMPLE.com/", true, http.StatusFound, "https://www.example.com/"},
		{"host the route does not serve", RedirectHost{WWW: WWWAdd, Hosts: []string{"example.com"}},
			"http://evil.test/", true, http.StatusOK, ""},
		{"escaped path", RedirectHost{WWW: WWWAdd}, "http://example.com/a%2Fb", true,
			http.StatusFound, "https://www.example.com/a%2Fb"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
			req := httptest.NewRequest(http.MethodGet, c.url, nil)
			if c.tls {
				req.TLS = &tls.ConnectionState{}
			}
			rec := httptest.NewRecorder()
			c.rh.Middleware(next).ServeHTTP(rec, req)
			if rec.Code != c.wantCode {
				t.Fatalf("status = %d, want %d", rec.Code, c.wantCode)
			}
			if got := rec.Header().Get("Location"); got != c.wantLoc {
				t.Fatalf("Location = %q, want %q", got, c.wantLoc)
			}
		})
	}
}
