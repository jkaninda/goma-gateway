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
	"errors"
	"net"
	"net/http"
	"net/http/pprof"
	"time"
)

// startPprof starts the opt-in Go profiling listener on addr (GOMA_PPROF_ADDR)
// and returns its server, or nil when addr is empty. It is off unless the
// variable is set, so a normal deployment never opens the port.
//
// The handlers are mounted on their own mux, never on the gateway's routers, so
// profiling is only reachable on this listener. The endpoints are
// unauthenticated and expose memory contents, command-line arguments and
// goroutine stacks: bind to a loopback address.
func startPprof(addr string) *http.Server {
	if addr == "" {
		return nil
	}
	srv := &http.Server{
		Addr:              addr,
		Handler:           pprofHandler(),
		ReadHeaderTimeout: time.Duration(defaultReadHeaderTimeout) * time.Second,
	}
	if isLoopbackAddr(addr) {
		logger.Warn("pprof listener enabled", "addr", addr)
	} else {
		logger.Warn("pprof listener enabled on a non-loopback address; its unauthenticated endpoints are reachable from other hosts",
			"addr", addr)
	}
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("pprof listener failed", "addr", addr, "error", err)
		}
	}()
	return srv
}

// pprofHandler serves the standard /debug/pprof/ endpoints. Index also serves
// the named profiles (heap, goroutine, allocs, block, mutex, threadcreate).
func pprofHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	return mux
}

// isLoopbackAddr reports whether a listen address only accepts local
// connections. An empty host (":6060") listens on every interface.
func isLoopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil || host == "" {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
