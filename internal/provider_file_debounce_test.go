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
