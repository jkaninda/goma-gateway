/*
 * Copyright 2024 Jonas Kaninda — Apache-2.0
 */

package internal

import "testing"

// With no database loaded (the default in tests) geoCountry must degrade
// gracefully to "" for any input — analytics keeps working without geo.
func TestGeoCountryGracefulWithoutDB(t *testing.T) {
	for _, ip := range []string{"8.8.8.8", "2001:4860:4860::8888", "not-an-ip", "", "192.168.1.1"} {
		if got := geoCountry(ip); got != "" {
			t.Errorf("geoCountry(%q) = %q, want \"\" (no DB loaded)", ip, got)
		}
	}
}
