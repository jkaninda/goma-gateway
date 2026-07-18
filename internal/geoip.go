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
	"sync"

	goutils "github.com/jkaninda/go-utils"
	"github.com/oschwald/geoip2-golang"
)

// defaultGeoIPPath is where Miabi drops the GeoIP database into the gateway.
// The .mmdb format is used by both MaxMind (GeoLite2-Country.mmdb) and
// IP2Location (IP2LOCATION-*.MMDB) — both expose a `country.iso_code`, so one
// reader covers either provider. Override with GOMA_GEOIP_DB.
const defaultGeoIPPath = "/etc/goma/GeoLite2-Country.mmdb"

var (
	geoOnce   sync.Once
	geoReader *geoip2.Reader
)

// initGeoIP opens the GeoIP database once, from GOMA_GEOIP_DB (default
// /etc/goma/GeoLite2-Country.mmdb). It is a no-op — country enrichment stays
// off, `geoCountry` returns "" — when the file is absent or unreadable, so
// analytics keeps working without geo. Called from initAnalytics.
func initGeoIP() {
	geoOnce.Do(func() {
		path := goutils.Env("GOMA_GEOIP_DB", defaultGeoIPPath)
		r, err := geoip2.Open(path)
		if err != nil {
			logger.Warn("GeoIP database not loaded; country enrichment disabled",
				"path", path, "error", err)
			return
		}
		geoReader = r
		logger.Info("GeoIP database loaded", "path", path)
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
