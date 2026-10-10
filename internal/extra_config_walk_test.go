/*
 * Copyright 2024 Jonas Kaninda — Apache-2.0
 */

package internal

import (
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// A writer that saves through a hidden temp file and renames it into place
// (editors, config controllers, the benchmark harness) must never make a load
// come back short. A temp file listed by the directory read and renamed away
// before it was examined used to abort the walk, and loadAllFiles then
// returned no files at all, so the gateway applied an empty configuration.
func TestLoadAllFilesDuringAtomicRenames(t *testing.T) {
	dir := t.TempDir()
	const files = 200
	for i := 0; i < files; i++ {
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("route-%d.yml", i)), []byte("routes: []\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	var stop atomic.Bool
	done := make(chan struct{})
	go func() {
		defer close(done)
		for n := 0; !stop.Load(); n++ {
			name := fmt.Sprintf("route-%d.yml", n%files)
			tmp := filepath.Join(dir, "."+name+".tmp")
			if err := os.WriteFile(tmp, []byte("routes: []\n"), 0o600); err != nil {
				return
			}
			if err := os.Rename(tmp, filepath.Join(dir, name)); err != nil {
				return
			}
		}
	}()
	defer func() { stop.Store(true); <-done }()

	deadline := time.Now().Add(2 * time.Second)
	for loads := 0; time.Now().Before(deadline); loads++ {
		got, err := loadAllFiles(dir)
		if err != nil {
			t.Fatalf("load %d: %v", loads, err)
		}
		if len(got) != files {
			t.Fatalf("load %d returned %d files, want %d", loads, len(got), files)
		}
	}
}
