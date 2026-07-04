/*
Copyright 2024 Jonas Kaninda

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package middlewares

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRewriteRegexInjectsToken(t *testing.T) {
	cases := []struct {
		name        string
		pattern     string
		replacement string
		path        string
		header      map[string]string
		want        string
	}{
		{
			name:        "workspace name replaced by header value",
			pattern:     `^/v2/[^/]+/(.*)`,
			replacement: `/v2/{{goma.headers.X-Workspace-Id}}/$1`,
			path:        "/v2/acme/frontend/blobs/uploads/",
			header:      map[string]string{"X-Workspace-Id": "ws_1"},
			want:        "/v2/ws_1/frontend/blobs/uploads/",
		},
		{
			name:        "plain regex rewrite still works",
			pattern:     `^/oldpath/(.*)`,
			replacement: `/newpath/$1`,
			path:        "/oldpath/foo",
			want:        "/newpath/foo",
		},
		{
			name:        "missing header resolves to empty",
			pattern:     `^/v2/[^/]+/(.*)`,
			replacement: `/v2/{{goma.headers.X-Workspace-Id}}/$1`,
			path:        "/v2/acme/x",
			want:        "/v2//x",
		},
		{
			name:        "whitespace inside token tolerated",
			pattern:     `^/v2/[^/]+/(.*)`,
			replacement: `/v2/{{ goma.headers.X-Workspace-Id }}/$1`,
			path:        "/v2/acme/x",
			header:      map[string]string{"X-Workspace-Id": "ws_42"},
			want:        "/v2/ws_42/x",
		},
		{
			name:        "query param replaced by query value",
			pattern:     `^/v2/[^/]+/(.*)`,
			replacement: `/v2/{{goma.query.workspace}}/$1`,
			path:        "/v2/acme/frontend?workspace=ws_9",
			want:        "/v2/ws_9/frontend",
		},
		{
			name:        "query param with underscore in name",
			pattern:     `^/v2/[^/]+/(.*)`,
			replacement: `/v2/{{goma.query.workspace_id}}/$1`,
			path:        "/v2/acme/x?workspace_id=ws_7",
			want:        "/v2/ws_7/x",
		},
		{
			name:        "missing query param resolves to empty",
			pattern:     `^/v2/[^/]+/(.*)`,
			replacement: `/v2/{{goma.query.workspace}}/$1`,
			path:        "/v2/acme/x",
			want:        "/v2//x",
		},
		{
			name:        "header and query tokens combined",
			pattern:     `^/v2/[^/]+/(.*)`,
			replacement: `/v2/{{goma.headers.X-Workspace-Id}}/{{goma.query.env}}/$1`,
			path:        "/v2/acme/x?env=prod",
			header:      map[string]string{"X-Workspace-Id": "ws_1"},
			want:        "/v2/ws_1/prod/x",
		},
		{
			name:        "header value with path separators is escaped to a single segment",
			pattern:     `^/v2/[^/]+/(.*)`,
			replacement: `/v2/{{goma.headers.X-Workspace-Id}}/$1`,
			path:        "/v2/acme/x",
			header:      map[string]string{"X-Workspace-Id": "../../admin"},
			want:        "/v2/..%2F..%2Fadmin/x",
		},
		{
			name:        "query value with path separators is escaped to a single segment",
			pattern:     `^/v2/[^/]+/(.*)`,
			replacement: `/v2/{{goma.query.workspace}}/$1`,
			path:        "/v2/acme/x?workspace=%2E%2E%2Fadmin",
			want:        "/v2/..%2Fadmin/x",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rr := &RewriteRegex{Pattern: tc.pattern, Replacement: tc.replacement}
			var got string
			h := rr.RewriteRegexMiddleware(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				got = r.URL.Path
			}))

			req := httptest.NewRequest(http.MethodPost, tc.path, nil)
			for k, v := range tc.header {
				req.Header.Set(k, v)
			}
			h.ServeHTTP(httptest.NewRecorder(), req)

			if got != tc.want {
				t.Fatalf("rewritten path = %q, want %q", got, tc.want)
			}
		})
	}
}
