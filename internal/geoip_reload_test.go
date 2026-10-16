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
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/oschwald/geoip2-golang"
)

// fakeCountryDB resolves every address to the code its file contained.
type fakeCountryDB struct{ code string }

func (f fakeCountryDB) Country(net.IP) (*geoip2.Country, error) {
	var c geoip2.Country
	c.Country.IsoCode = f.code
	return &c, nil
}

// fakeGeoIP points the watcher at paths whose content is the country code; "bad" fails to open.
func fakeGeoIP(t *testing.T, paths ...string) (w *geoIPWatcher, opens *int) {
	t.Helper()
	n := 0
	prevOpen, prevWatcher := openCountryDB, geoWatcher
	openCountryDB = func(path string) (countryDB, error) {
		n++
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		if s := strings.TrimSpace(string(b)); s != "bad" {
			return fakeCountryDB{code: s}, nil
		}
		return nil, errors.New("corrupt database")
	}
	geo.Store(nil)
	w = &geoIPWatcher{paths: paths, sleep: func(time.Duration) {}}
	geoWatcher = w
	t.Cleanup(func() {
		openCountryDB, geoWatcher = prevOpen, prevWatcher
		geo.Store(nil)
	})
	return w, &n
}

var bump = time.Now()

// writeDB writes content with a fresh mtime, as a real replacement would carry.
func writeDB(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	bump = bump.Add(time.Minute)
	if err := os.Chtimes(path, bump, bump); err != nil {
		t.Fatal(err)
	}
}

func wantCountry(t *testing.T, want string) {
	t.Helper()
	if got := geoCountry("203.0.113.9"); got != want {
		t.Fatalf("geoCountry = %q, want %q", got, want)
	}
}

func TestGeoIPReloadsAChangedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "country.mmdb")
	writeDB(t, path, "DE")
	w, opens := fakeGeoIP(t, path)

	if !w.check(false) {
		t.Fatal("initial load failed")
	}
	wantCountry(t, "DE")

	w.check(true)
	if *opens != 1 {
		t.Fatalf("an unchanged file was reopened (%d opens)", *opens)
	}

	writeDB(t, path, "FR")
	w.check(true)
	wantCountry(t, "FR")
}

func TestGeoIPKeepsThePreviousDatabaseWhenTheNewOneIsBad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "country.mmdb")
	writeDB(t, path, "DE")
	w, opens := fakeGeoIP(t, path)
	w.check(false)

	writeDB(t, path, "bad")
	w.check(true)
	wantCountry(t, "DE")
	w.check(true)
	if *opens != 2 {
		t.Fatalf("a file that already failed was retried (%d opens, want 2)", *opens)
	}

	writeDB(t, path, "NL")
	w.check(true)
	wantCountry(t, "NL")
}

func TestGeoIPWaitsForAFileStillBeingWritten(t *testing.T) {
	path := filepath.Join(t.TempDir(), "country.mmdb")
	writeDB(t, path, "DE")
	w, _ := fakeGeoIP(t, path)
	w.check(false)

	writeDB(t, path, "F")
	w.sleep = func(time.Duration) { writeDB(t, path, "FR") }
	w.check(true)
	wantCountry(t, "DE")

	w.sleep = func(time.Duration) {}
	w.check(true)
	wantCountry(t, "FR")
}

func TestGeoIPPicksUpADatabaseAddedAfterStartup(t *testing.T) {
	dir := t.TempDir()
	primary, fallback := filepath.Join(dir, "country.mmdb"), filepath.Join(dir, "GeoLite2-Country.mmdb")
	w, _ := fakeGeoIP(t, primary, fallback)
	if w.check(false) {
		t.Fatal("reported a database with none on disk")
	}
	wantCountry(t, "")

	writeDB(t, fallback, "DE")
	w.check(true)
	wantCountry(t, "DE")

	writeDB(t, primary, "FR")
	w.check(true)
	wantCountry(t, "FR")
}

func TestGeoIPLookupsDuringReloads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "country.mmdb")
	writeDB(t, path, "DE")
	w, _ := fakeGeoIP(t, path)
	w.check(false)

	var wg sync.WaitGroup
	stop := make(chan struct{})
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					if c := geoCountry("203.0.113.9"); c != "DE" && c != "FR" {
						t.Errorf("lookup returned %q mid-reload", c)
						return
					}
				}
			}
		}()
	}
	for i := range 50 {
		writeDB(t, path, []string{"FR", "DE"}[i%2])
		w.check(true)
	}
	close(stop)
	wg.Wait()
}

func TestGeoIPReloadInterval(t *testing.T) {
	cases := map[string]time.Duration{
		"":      defaultGeoIPReloadInterval,
		"off":   0,
		"0":     0,
		"3m":    3 * time.Minute,
		"30s":   minGeoIPReloadInterval,
		"never": defaultGeoIPReloadInterval,
	}
	for raw, want := range cases {
		if got := (GeoIPConfig{ReloadInterval: raw}).reloadInterval(); got != want {
			t.Errorf("reloadInterval(%q) = %s, want %s", raw, got, want)
		}
	}
	t.Setenv("GOMA_GEOIP_RELOAD_INTERVAL", "off")
	if got := (GeoIPConfig{ReloadInterval: "3m"}).reloadInterval(); got != 0 {
		t.Errorf("env off must override the config, got %s", got)
	}
}
