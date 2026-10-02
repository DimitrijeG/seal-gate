package main

import (
	"bytes"
	"fmt"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Node is one package in the module.
type Node struct {
	ID       string `json:"id"`       // full import path, stable across rebuilds
	Rel      string `json:"rel"`      // path relative to the module root
	Label    string `json:"label"`    // short name shown in the box
	Category string `json:"category"` // architectural layer, used for colour
	Files    int    `json:"files"`
}

// Edge is one import.
type Edge struct {
	From string `json:"from"`
	To   string `json:"to"`
	Rule string `json:"rule,omitempty"` // the rule this edge breaks, if any
}

// Graph is the whole payload sent to the browser.
type Graph struct {
	Module     string      `json:"module"`
	Nodes      []Node      `json:"nodes"`
	Edges      []Edge      `json:"edges"`
	Violations []Violation `json:"violations"`
	BuiltAt    time.Time   `json:"builtAt"`
	// Warning is go list's stderr when it still produced a usable graph, as mid-edit.
	Warning string `json:"warning,omitempty"`
}

// Load shells out to go list: no dependencies, and fast enough to run on every save.
func Load(dir string) (*Graph, error) {
	module, err := modulePath(dir)
	if err != nil {
		return nil, err
	}

	const format = "{{.ImportPath}}\t{{len .GoFiles}}\t{{join .Imports \",\"}}"

	cmd := exec.Command("go", "list", "-e", "-f", format, "./...")
	cmd.Dir = dir

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	runErr := cmd.Run()

	// An empty module looks like a failure (no stdout) unless stderr is checked.
	if stdout.Len() == 0 {
		if strings.Contains(stderr.String(), "matched no packages") {
			return &Graph{Module: module, BuiltAt: time.Now()}, nil
		}
		return nil, fmt.Errorf("go list: %v: %s", runErr, strings.TrimSpace(stderr.String()))
	}

	graph := &Graph{
		Module:  module,
		BuiltAt: time.Now(),
	}
	if stderr.Len() > 0 {
		// Keep the graph: one that blanks on every half-typed brace goes unused.
		graph.Warning = firstLine(stderr.String())
	}

	known := make(map[string]bool)
	type pending struct {
		from    string
		imports []string
	}
	var rows []pending

	for _, line := range strings.Split(stdout.String(), "\n") {
		// Not TrimSpace: a package with no imports ends in a tab that must survive.
		fields := strings.Split(strings.TrimRight(line, "\r"), "\t")
		if len(fields) != 3 {
			continue
		}

		importPath := fields[0]
		files, _ := strconv.Atoi(fields[1])

		rel := relPath(module, importPath)
		graph.Nodes = append(graph.Nodes, Node{
			ID:       importPath,
			Rel:      rel,
			Label:    label(rel),
			Category: categorize(rel),
			Files:    files,
		})
		known[importPath] = true

		var imports []string
		if fields[2] != "" {
			imports = strings.Split(fields[2], ",")
		}
		rows = append(rows, pending{from: importPath, imports: imports})
	}

	// Internal edges only: external imports are noise and always legal.
	for _, row := range rows {
		for _, imp := range row.imports {
			if !known[imp] {
				continue
			}
			graph.Edges = append(graph.Edges, Edge{From: row.from, To: imp})
		}
	}

	sort.Slice(graph.Nodes, func(i, j int) bool { return graph.Nodes[i].Rel < graph.Nodes[j].Rel })
	sort.Slice(graph.Edges, func(i, j int) bool {
		if graph.Edges[i].From != graph.Edges[j].From {
			return graph.Edges[i].From < graph.Edges[j].From
		}
		return graph.Edges[i].To < graph.Edges[j].To
	})

	Apply(graph)

	return graph, nil
}

func modulePath(dir string) (string, error) {
	cmd := exec.Command("go", "list", "-m")
	cmd.Dir = dir

	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("go list -m in %s: %w", dir, err)
	}

	return strings.TrimSpace(string(out)), nil
}

func relPath(module, importPath string) string {
	if rel, ok := strings.CutPrefix(importPath, module+"/"); ok {
		return rel
	}
	return importPath
}

// label drops internal/, which every non-cmd node shares.
func label(rel string) string {
	return strings.TrimPrefix(rel, "internal/")
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return strings.TrimSpace(s)
}
