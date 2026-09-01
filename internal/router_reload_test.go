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
	"time"

	"github.com/jkaninda/njia"
)

func newTestRouter(t *testing.T, handler http.Handler) *router {
	t.Helper()
	table := newProxyRouter(false)
	if err := table.HandleFunc(http.MethodGet, "/live", handler.ServeHTTP); err != nil {
		t.Fatal(err)
	}
	r := &router{strictSlash: false}
	r.setTable(table)
	return r
}

func TestReloadIsNotBlockedByInFlightRequests(t *testing.T) {
	release := make(chan struct{})
	started := make(chan struct{})

	r := newTestRouter(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(started)
		<-release // stands in for a long-lived connection
		w.WriteHeader(http.StatusOK)
	}))

	go func() {
		r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/live", nil))
	}()
	<-started

	swapped := make(chan struct{})
	go func() {
		next := newProxyRouter(false)
		_ = next.HandleFunc(http.MethodGet, "/live", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusTeapot)
		})
		r.swapTable(next)
		close(swapped)
	}()

	select {
	case <-swapped:
	case <-time.After(5 * time.Second):
		close(release)
		t.Fatal("the table swap blocked behind an in-flight request")
	}

	served := make(chan int, 1)
	go func() {
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/live", nil))
		served <- rec.Code
	}()

	select {
	case code := <-served:
		if code != http.StatusTeapot {
			t.Errorf("new request served by the old table: got %d", code)
		}
	case <-time.After(5 * time.Second):
		close(release)
		t.Fatal("a new request blocked while a reload was in progress")
	}

	close(release)
}

func TestReloadFromInsideARequestDoesNotDeadlock(t *testing.T) {
	var r *router

	r = newTestRouter(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		next := newProxyRouter(false)
		_ = next.HandleFunc(http.MethodGet, "/live", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusTeapot)
		})
		r.swapTable(next) // what the reload handler ends up doing
		w.WriteHeader(http.StatusOK)
	}))

	done := make(chan struct{})
	go func() {
		r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/live", nil))
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("swapping the table from inside a request deadlocked")
	}
}

func TestConcurrentReloadsAndTraffic(t *testing.T) {
	r := newTestRouter(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	stop := make(chan struct{})
	var readers int
	for i := 0; i < 8; i++ {
		readers++
		go func() {
			for {
				select {
				case <-stop:
					return
				default:
					r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/live", nil))
				}
			}
		}()
	}

	for i := 0; i < 200; i++ {
		next := newProxyRouter(false)
		_ = next.HandleFunc(http.MethodGet, "/live", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
		r.swapTable(next)
	}
	close(stop)
	time.Sleep(50 * time.Millisecond)
}

var _ = njia.Router{}
