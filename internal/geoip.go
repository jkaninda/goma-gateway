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
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/oschwald/geoip2-golang"
)

// defaultGeoIPPaths are the databases Goma looks for when GOMA_GEOIP_DB is unset,
// tried in order.
//
// `country.mmdb` is the provider-neutral name, and the one the docs use: the .mmdb
// format is shared by MaxMind, DB-IP and IP2Location, and all three expose a
// `country.iso_code`, so one reader covers whichever the operator supplied — naming
// the file after any one of them was always a little wrong.
//
// GeoLite2-Country.mmdb stays as a fallback. It is what Goma defaulted to, and what
// MaxMind's own download is called, so operators land on it without thinking.
//
// /etc/goma/geoip/ comes first: mount a directory there, not a single file. A
// single-file bind mount pins the original inode, so an update written by rename
// (geoipupdate, mv) never reaches the container and hot reload sees nothing.
var defaultGeoIPPaths = []string{
	"/etc/goma/geoip/country.mmdb",
	"/etc/goma/geoip/GeoLite2-Country.mmdb",
	"/etc/goma/country.mmdb",
	"/etc/goma/GeoLite2-Country.mmdb",
}

const (
	defaultGeoIPReloadInterval = 5 * time.Minute
	minGeoIPReloadInterval     = time.Minute
	// geoIPSettle is how long a changed file must stay unchanged before it is loaded,
	// so a database still being copied into place is not read half-written.
	geoIPSettle = 2 * time.Second
)

type countryDB interface {
	Country(net.IP) (*geoip2.Country, error)
}

// geoDB is the loaded database and the file state it was read from. It is swapped
// atomically, so lookups never block on a reload and never see a half-built reader.
type geoDB struct {
	db   countryDB
	path string
	stat fileStamp
}

type fileStamp struct {
	size int64
	mod  time.Time
}

var (
	geoOnce    sync.Once
	geo        atomic.Pointer[geoDB]
	geoWatcher *geoIPWatcher
)

// openCountryDB reads the whole file instead of memory-mapping it: an operator
// overwriting the file in place would otherwise crash the gateway (SIGBUS).
var openCountryDB = func(path string) (countryDB, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	r, err := geoip2.FromBytes(data)
	if err != nil {
		return nil, err
	}
	if _, err := r.Country(net.IPv4(1, 1, 1, 1)); err != nil {
		return nil, fmt.Errorf("not a country database: %w", err)
	}
	return r, nil
}

// geoIPWatcher reloads the database when its file changes, so an updated
// country.mmdb takes effect without restarting the gateway.
type geoIPWatcher struct {
	paths []string
	mu    sync.Mutex
	// failed is the file state that last failed to load; it is not retried until the file changes again.
	failed fileStamp
	sleep  func(time.Duration)
}

func initGeoIP(dbPath string) {
	geoOnce.Do(func() {
		paths := defaultGeoIPPaths
		if p := strings.TrimSpace(dbPath); p != "" {
			paths = []string{p}
		}
		geoWatcher = &geoIPWatcher{paths: paths, sleep: time.Sleep}
		if !geoWatcher.check(false) {
			logger.Warn("GeoIP database not loaded; country enrichment disabled until one appears", "paths", paths)
		}
	})
}

// watchGeoIP polls for a changed database until ctx ends. interval <= 0 disables it.
func watchGeoIP(ctx context.Context, interval time.Duration) {
	if geoWatcher == nil || interval <= 0 {
		return
	}
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				geoWatcher.check(true)
			}
		}
	}()
}

// reloadGeoIP checks the database file now, for the on-demand reload endpoint.
func reloadGeoIP() {
	if geoWatcher != nil {
		geoWatcher.check(true)
	}
}

// check loads the first existing database if it differs from the one in use and
// reports whether a database is loaded afterwards. settle waits out a file still
// being written; the initial load skips it, since nothing is serving yet.
func (w *geoIPWatcher) check(settle bool) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	cur := geo.Load()
	path, stamp, ok := w.locate()
	if !ok || (cur != nil && cur.path == path && cur.stat == stamp) || stamp == w.failed {
		return cur != nil
	}
	if settle {
		w.sleep(geoIPSettle)
		if again, err := statStamp(path); err != nil || again != stamp {
			return cur != nil
		}
	}
	db, err := openCountryDB(path)
	if err != nil {
		w.failed = stamp
		logger.Warn("GeoIP database not loaded; keeping the previous one", "path", path, "error", err)
		return cur != nil
	}
	geo.Store(&geoDB{db: db, path: path, stat: stamp})
	if cur == nil {
		logger.Info("GeoIP database loaded", "path", path)
	} else {
		logger.Info("GeoIP database reloaded", "path", path)
	}
	return true
}

func (w *geoIPWatcher) locate() (string, fileStamp, bool) {
	for _, p := range w.paths {
		if st, err := statStamp(p); err == nil {
			return p, st, true
		}
	}
	return "", fileStamp{}, false
}

func statStamp(path string) (fileStamp, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return fileStamp{}, err
	}
	if fi.IsDir() {
		return fileStamp{}, fmt.Errorf("%s is a directory", path)
	}
	return fileStamp{size: fi.Size(), mod: fi.ModTime()}, nil
}

// closeGeoIP drops the loaded database.
func closeGeoIP() {
	geo.Store(nil)
}

// geoCountry resolves an IP to an ISO country code at the edge; the caller then
// discards the raw IP (no IP is ever emitted). Returns "" when no database is
// loaded or the lookup fails (e.g. a private or invalid address).
func geoCountry(ip string) string {
	cur := geo.Load()
	if cur == nil || ip == "" {
		return ""
	}
	netIP := net.ParseIP(ip)
	if netIP == nil {
		return ""
	}
	rec, err := cur.db.Country(netIP)
	if err != nil || rec == nil {
		return ""
	}
	return rec.Country.IsoCode
}
