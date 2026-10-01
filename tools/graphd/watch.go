package main

import (
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// fingerprint polls instead of using fsnotify, keeping the tool dependency-free.
// Walking a tree this size every few hundred milliseconds costs nothing.
func fingerprint(dir string) string {
	var b strings.Builder

	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}

		if d.IsDir() {
			// Skip what go list skips, so edits there don't trigger rebuilds.
			name := d.Name()
			if path != dir && (strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") ||
				name == "testdata" || name == "vendor" || name == "node_modules") {
				return filepath.SkipDir
			}
			return nil
		}

		if !strings.HasSuffix(path, ".go") && d.Name() != "go.mod" {
			return nil
		}

		info, err := d.Info()
		if err != nil {
			return nil
		}

		b.WriteString(path)
		b.WriteByte(0)
		b.WriteString(strconv.FormatInt(info.ModTime().UnixNano(), 36))
		b.WriteByte(0)
		b.WriteString(strconv.FormatInt(info.Size(), 36))
		b.WriteByte('\n')

		return nil
	})

	return b.String()
}

// Watch calls onChange once at startup and on every change, and blocks.
// Polling debounces for free: an editor's several writes per save share a tick.
func Watch(dir string, interval time.Duration, onChange func()) {
	previous := fingerprint(dir)
	onChange()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for range ticker.C {
		current := fingerprint(dir)
		if current == previous {
			continue
		}

		previous = current
		onChange()
	}
}
