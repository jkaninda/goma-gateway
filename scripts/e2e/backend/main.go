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

// Command backend is the mock upstream for scripts/e2e/run.sh. It answers
// every request with its name, so the e2e checks can tell which backend a
// request reached.
//
//	backend -addr 127.0.0.1:9001 -name a   serve
//	backend -free-ports 3                  print 3 free loopback ports and exit
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:0", "listen address")
	name := flag.String("name", "backend", "name returned in every response body")
	freePorts := flag.Int("free-ports", 0, "print this many free loopback ports and exit")
	flag.Parse()

	if *freePorts > 0 {
		ports, err := pickFreePorts(*freePorts)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(strings.Join(ports, " "))
		return
	}

	srv := &http.Server{
		Addr: *addr,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = fmt.Fprint(w, *name)
		}),
		ReadHeaderTimeout: 5 * time.Second,
	}
	if err := srv.ListenAndServe(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// pickFreePorts holds every listener open until all ports are chosen, so the
// same port is never returned twice.
func pickFreePorts(n int) ([]string, error) {
	ports := make([]string, 0, n)
	listeners := make([]net.Listener, 0, n)
	defer func() {
		for _, ln := range listeners {
			_ = ln.Close()
		}
	}()
	for i := 0; i < n; i++ {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return nil, err
		}
		listeners = append(listeners, ln)
		_, port, _ := net.SplitHostPort(ln.Addr().String())
		ports = append(ports, port)
	}
	return ports, nil
}
