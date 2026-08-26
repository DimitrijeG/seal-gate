package main

import (
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// fingerprint summarises the state of every .go file under dir.
//
// This polls rather than using fsnotify, which keeps the tool dependency-free.
// Walking ~100 files every few hundred milliseconds costs nothing; if this ever
// runs over a tree large enough for the walk to show up in a profile, swap in
// fsnotify behind the same Watch signature.
func fingerprint(dir string) string {
	var b strings.Builder

	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}

		if d.IsDir() {
			switch d.Name() {
			case ".git", "vendor", "node_modules":
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

// Watch calls onChange whenever the tree's fingerprint changes, and once at
// startup. It blocks.
//
// Polling gives debouncing for free: an editor's several write events for one
// save collapse into a single tick.
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
