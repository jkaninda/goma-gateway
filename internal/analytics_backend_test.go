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

func captureEvents(t *testing.T) chan *AnalyticsEvent {
	t.Helper()
	prev := analytics
	ch := make(chan *AnalyticsEvent, 8)
	analytics = &analyticsEmitter{ch: ch, sample: 1}
	t.Cleanup(func() { analytics = prev })
	return ch
}

func okServer(t *testing.T) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	t.Cleanup(s.Close)
	return s
}

func serveOnce(t *testing.T, h http.Handler, header, value string) *AnalyticsEvent {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if header != "" {
		req.Header.Set(header, value)
	}
	h.ServeHTTP(httptest.NewRecorder(), req)
	select {
	case e := <-analytics.ch:
		return e
	default:
		t.Fatal("no analytics event emitted")
		return nil
	}
}

func TestAnalyticsEventNamesTheCanaryBackend(t *testing.T) {
	resetUnavailable()
	captureEvents(t)
	stable, canary := okServer(t), okServer(t)
	pr := &ProxyRoute{name: "r", canaryBased: true, backends: Backends{
		{Endpoint: stable.URL, Weight: 100},
		{Endpoint: canary.URL, Exclusive: true, Match: []BackendMatch{
			{Source: SourceTypeHeader, Name: "X-Canary", Operator: OperatorEquals, Value: "1"},
		}},
	}}
	h := (&ProxyMiddleware{Name: "r"}).Wrap(pr.ProxyHandler())

	if e := serveOnce(t, h, "X-Canary", "1"); e.Backend != canary.URL {
		t.Errorf("matched request: backend = %q, want canary %q", e.Backend, canary.URL)
	}
	if e := serveOnce(t, h, "", ""); e.Backend != stable.URL {
		t.Errorf("unmatched request: backend = %q, want stable %q", e.Backend, stable.URL)
	}
}

func TestAnalyticsEventOmitsBackendForASingleBackend(t *testing.T) {
	captureEvents(t)
	only := okServer(t)
	pr := &ProxyRoute{name: "r", backends: Backends{{Endpoint: only.URL}}}
	h := (&ProxyMiddleware{Name: "r"}).Wrap(pr.ProxyHandler())
	if e := serveOnce(t, h, "", ""); e.Backend != "" {
		t.Errorf("backend = %q, want empty", e.Backend)
	}
}
