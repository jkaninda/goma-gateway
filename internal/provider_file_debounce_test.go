/*
 * Copyright 2024 Jonas Kaninda — Apache-2.0
 */

package internal

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFileProviderDebounceDuration(t *testing.T) {
	cases := []struct {
		raw  string
		want time.Duration
	}{
		{"", defaultWatchDebounce},
		{"  ", defaultWatchDebounce},
		{"0s", 0},
		{"50ms", 50 * time.Millisecond},
		{"-1s", 0},
		{"not-a-duration", defaultWatchDebounce},
	}
	for _, c := range cases {
		p := &fileProvider{config: &FileProvider{Debounce: c.raw}}
		if got := p.debounceDuration(); got != c.want {
			t.Errorf("debounce %q: got %v, want %v", c.raw, got, c.want)
		}
	}
}

// startWatch runs the file provider's watcher on a fresh directory and returns
// the directory and the channel bundles arrive on, with the initial load drained.
func startWatch(t *testing.T, debounce string) (string, <-chan *ConfigBundle) {
	t.Helper()
	dir := t.TempDir()
	prov, err := NewFileProvider(&FileProvider{Enabled: true, Directory: dir, Watch: true, Debounce: debounce})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	out := make(chan *ConfigBundle, 64)
	if err := prov.Watch(ctx, out); err != nil {
		t.Fatal(err)
	}
	select {
	case <-out:
	case <-time.After(2 * time.Second):
		t.Fatal("no initial load")
	}
	return dir, out
}

func writeRoute(t *testing.T, dir string, i int) {
	t.Helper()
	doc := fmt.Sprintf("routes:\n  - name: r%d\n    path: /r%d\n    target: http://127.0.0.1:9\n", i, i)
	if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("r%d.yaml", i)), []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
}

// With debouncing off, changes spaced well apart must each be applied.
func TestFileProviderNoDebounceAppliesEachChange(t *testing.T) {
	dir, out := startWatch(t, "0s")
	for i := 1; i <= 3; i++ {
		writeRoute(t, dir, i)
		deadline := time.After(2 * time.Second)
	wait:
		for {
			select {
			case b := <-out:
				if len(b.Routes) == i {
					break wait
				}
			case <-deadline:
				t.Fatalf("change %d was not applied", i)
			}
		}
	}
}

// A writer that never pauses for longer than the debounce window must still see
// its changes applied while it is writing, not only after it stops.
func TestFileProviderDebounceHasCeiling(t *testing.T) {
	const window = 100 * time.Millisecond
	dir, out := startWatch(t, window.String())

	stop := time.After(4 * window * 3)
	tick := time.NewTicker(window / 2)
	defer tick.Stop()
	reloads := 0
	for i := 1; ; i++ {
		select {
		case <-tick.C:
			writeRoute(t, dir, i)
		case <-out:
			reloads++
		case <-stop:
			if reloads == 0 {
				t.Fatal("no reload during a continuous stream of writes; the debounce has no ceiling")
			}
			return
		}
	}
}

// With debouncing off, a burst of writes that arrives while a reload is
// blocked must collapse into a few reloads, not one per event, and the last
// one must reflect every write.
func TestFileProviderNoDebounceCoalescesBurst(t *testing.T) {
	dir := t.TempDir()
	prov, err := NewFileProvider(&FileProvider{Enabled: true, Directory: dir, Watch: true, Debounce: "0s"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	// Unbuffered and not read during the burst: the first reload blocks on
	// the send while the rest of the events queue behind it.
	out := make(chan *ConfigBundle)
	go func() { _ = prov.Watch(ctx, out) }()
	select {
	case <-out:
	case <-time.After(2 * time.Second):
		t.Fatal("no initial load")
	}

	const files = 200
	for i := 1; i <= files; i++ {
		writeRoute(t, dir, i)
	}
	time.Sleep(200 * time.Millisecond)

	bundles, routes := 0, 0
	for {
		select {
		case b := <-out:
			bundles++
			routes = len(b.Routes)
			continue
		case <-time.After(time.Second):
		}
		break
	}
	if routes != files {
		t.Fatalf("last bundle has %d routes, want %d", routes, files)
	}
	if bundles > 10 {
		t.Fatalf("%d writes produced %d reloads; queued events were not coalesced", files, bundles)
	}
}

func TestLatestBundle(t *testing.T) {
	ch := make(chan *ConfigBundle, 3)
	first := &ConfigBundle{Version: "1"}
	if got := latestBundle(first, ch); got != first {
		t.Fatal("with nothing queued, the received bundle must be returned")
	}
	ch <- &ConfigBundle{Version: "2"}
	ch <- &ConfigBundle{Version: "3"}
	if got := latestBundle(first, ch); got.Version != "3" {
		t.Fatalf("got version %q, want the newest (3)", got.Version)
	}
	if len(ch) != 0 {
		t.Fatal("queued bundles were not drained")
	}
}
