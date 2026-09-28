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
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestResponseHeadersApplyToEveryStatus(t *testing.T) {
	policy := ResponseHeader{Name: "security", SetHeaders: map[string]string{
		"X-Frame-Options":        "DENY",
		"X-Content-Type-Options": "nosniff",
	}}
	for _, status := range []int{http.StatusOK, http.StatusFound, http.StatusNotFound, http.StatusInternalServerError} {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := newResponseRecorder(httptest.NewRecorder(), req, false, []ResponseHeader{policy})
		rec.statusCode = status
		rec.applyResponseHeaders()
		if got := rec.Header().Get("X-Frame-Options"); got != "DENY" {
			t.Errorf("status %d: X-Frame-Options = %q, want DENY", status, got)
		}
	}
}
