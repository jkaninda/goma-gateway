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
	"net"
	"strings"
	"sync"

	goutils "github.com/jkaninda/go-utils"
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
var defaultGeoIPPaths = []string{
	"/etc/goma/country.mmdb",
	"/etc/goma/GeoLite2-Country.mmdb",
}

var (
	geoOnce   sync.Once
	geoReader *geoip2.Reader
)

// initGeoIP opens the GeoIP database once: GOMA_GEOIP_DB if set, otherwise the
// first of defaultGeoIPPaths that opens. It is a no-op — country enrichment stays
// off, `geoCountry` returns "" — when no database is readable, so analytics keeps
// working without geo. Called from initAnalytics.
func initGeoIP() {
	geoOnce.Do(func() {
		paths := defaultGeoIPPaths
		if p := strings.TrimSpace(goutils.Env("GOMA_GEOIP_DB", "")); p != "" {
			paths = []string{p}
		}
		var lastErr error
		for _, path := range paths {
			r, err := geoip2.Open(path)
			if err != nil {
				lastErr = err
				continue
			}
			geoReader = r
			logger.Info("GeoIP database loaded", "path", path)
			return
		}
		logger.Warn("GeoIP database not loaded; country enrichment disabled",
			"paths", paths, "error", lastErr)
	})
}

// closeGeoIP releases the memory-mapped database. Safe with no reader.
func closeGeoIP() {
	if geoReader != nil {
		_ = geoReader.Close()
		geoReader = nil
	}
}

// geoCountry resolves an IP to an ISO country code at the edge; the caller then
// discards the raw IP (no IP is ever emitted). Returns "" when no database is
// loaded or the lookup fails (e.g. a private or invalid address).
func geoCountry(ip string) string {
	if geoReader == nil || ip == "" {
		return ""
	}
	netIP := net.ParseIP(ip)
	if netIP == nil {
		return ""
	}
	rec, err := geoReader.Country(netIP)
	if err != nil || rec == nil {
		return ""
	}
	return rec.Country.IsoCode
}
