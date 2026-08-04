/*
 * Copyright 2024 Jonas Kaninda — Apache-2.0
 */

package middlewares

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// echo records what the upstream would actually receive.
func echo(seen *string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*seen = r.URL.RequestURI()
		w.WriteHeader(http.StatusOK)
	})
}

func TestStripQueryRemovesOnlyTheNamedParams(t *testing.T) {
	const uploads = `^/v2/.+/blobs/uploads/$`
	cases := []struct {
		name   string
		method string
		uri    string
		want   string
	}{
		{
			// The registry case: a cross-repository mount the gateway will not pass
			// on becomes an ordinary upload rather than a refused request.
			"mount hint is dropped",
			http.MethodPost,
			"/v2/tenant-a/app/blobs/uploads/?mount=sha256:abc&from=tenant-b/app",
			"/v2/tenant-a/app/blobs/uploads/",
		},
		{
			"unrelated params survive",
			http.MethodPost,
			"/v2/tenant-a/app/blobs/uploads/?mount=sha256:abc&digest=sha256:def",
			"/v2/tenant-a/app/blobs/uploads/?digest=sha256%3Adef",
		},
		{
			"a request without the params is untouched",
			http.MethodPost,
			"/v2/tenant-a/app/blobs/uploads/",
			"/v2/tenant-a/app/blobs/uploads/",
		},
		{
			// PATCH/PUT carry the actual blob upload; only the POST opens a mount.
			"other methods are out of scope",
			http.MethodPatch,
			"/v2/tenant-a/app/blobs/uploads/?mount=sha256:abc&from=tenant-b/app",
			// Out of scope: forwarded byte-for-byte, not re-encoded.
			"/v2/tenant-a/app/blobs/uploads/?mount=sha256:abc&from=tenant-b/app",
		},
		{
			"other paths are out of scope",
			http.MethodPost,
			"/v2/tenant-a/app/manifests/latest?mount=sha256:abc&from=tenant-b/app",
			"/v2/tenant-a/app/manifests/latest?mount=sha256:abc&from=tenant-b/app",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var seen string
			s := &StripQuery{
				Params:      []string{"mount", "from"},
				Methods:     []string{http.MethodPost},
				PathPattern: uploads,
			}
			req := httptest.NewRequest(tc.method, tc.uri, nil)
			s.StripQueryMiddleware(echo(&seen)).ServeHTTP(httptest.NewRecorder(), req)
			if seen != tc.want {
				t.Errorf("upstream saw %q, want %q", seen, tc.want)
			}
		})
	}
}

// An unparseable pattern must disable the rule, not widen it to every path.
func TestStripQueryInvalidPatternMatchesNothing(t *testing.T) {
	var seen string
	s := &StripQuery{Params: []string{"mount"}, PathPattern: "([unclosed"}
	req := httptest.NewRequest(http.MethodPost, "/v2/a/b/blobs/uploads/?mount=x", nil)
	s.StripQueryMiddleware(echo(&seen)).ServeHTTP(httptest.NewRecorder(), req)
	if seen != "/v2/a/b/blobs/uploads/?mount=x" {
		t.Errorf("upstream saw %q, want the request unchanged", seen)
	}
}
