package main

import (
	"os"
	"slices"
	"testing"
)

const defaultRepo = "../.."

func repoDir(t *testing.T) string {
	t.Helper()

	dir := os.Getenv("SEALGATE_DIR")
	if dir == "" {
		dir = defaultRepo
	}

	if _, err := os.Stat(dir); err != nil {
		t.Skipf("module not found at %s (set SEALGATE_DIR): %v", dir, err)
	}

	return dir
}

// TestArchitecture enforces the rules the server only draws in red.
func TestArchitecture(t *testing.T) {
	graph, err := Load(repoDir(t))
	if err != nil {
		t.Fatalf("load graph: %v", err)
	}

	if len(graph.Nodes) == 0 {
		t.Skip("module has no packages yet; nothing to check")
	}

	for _, v := range graph.Violations {
		t.Errorf("%s\n    %s -> %s\n    %s", v.Rule, v.From, v.To, v.Why)
	}

	t.Logf("%d packages, %d imports, %d violations",
		len(graph.Nodes), len(graph.Edges), len(graph.Violations))
}

func TestEveryPackageIsClassified(t *testing.T) {
	graph, err := Load(repoDir(t))
	if err != nil {
		t.Fatalf("load graph: %v", err)
	}

	for _, node := range graph.Nodes {
		if !classified(node.Rel) {
			t.Errorf("%s has no category; add it to domainPackages or infrastructurePackages", node.Rel)
		}
	}
}

// TestLoadCatchesKnownViolations proves the whole pipeline end to end, since a
// clean repo passes TestArchitecture even when the loader is broken.
func TestLoadCatchesKnownViolations(t *testing.T) {
	graph, err := Load("testdata/violations")
	if err != nil {
		t.Fatalf("load fixture: %v", err)
	}

	// storage/memory and cryptography import nothing, which once hid them.
	if len(graph.Nodes) != 4 {
		t.Errorf("got %d packages, want 4", len(graph.Nodes))
	}

	type hit struct{ rule, from, to string }
	var got []hit
	for _, v := range graph.Violations {
		got = append(got, hit{v.Rule, v.From, v.To})
	}

	want := []hit{
		{"domain-no-infrastructure", "internal/system", "internal/cryptography"},
		{"only-app-knows-backends", "internal/repository", "internal/storage/memory"},
	}
	if !slices.Equal(got, want) {
		t.Errorf("violations:\n got  %v\n want %v", got, want)
	}
}

func TestCyclePathStartsAtTheCycle(t *testing.T) {
	g := &Graph{
		Nodes: []Node{{ID: "a", Rel: "a"}, {ID: "b", Rel: "b"}, {ID: "c", Rel: "c"}},
		Edges: []Edge{{From: "a", To: "b"}, {From: "b", To: "c"}, {From: "c", To: "b"}},
	}
	Apply(g)

	if len(g.Violations) != 1 {
		t.Fatalf("got %d violations, want 1: %v", len(g.Violations), g.Violations)
	}
	if want := "cycle: b -> c -> b"; g.Violations[0].Why != want {
		t.Errorf("got %q, want %q", g.Violations[0].Why, want)
	}
}

func TestRulePredicates(t *testing.T) {
	cases := []struct {
		name, from, to, want string
	}{
		{"domain reaching into storage", "internal/secrets", "internal/storage/postgres", "domain-no-infrastructure"},
		{"domain reaching into the barrier", "internal/identity", "internal/barrier", "domain-no-infrastructure"},
		{"domain subpackage reaching into crypto", "internal/secrets/kv", "internal/cryptography", "domain-no-infrastructure"},
		{"http querying storage", "internal/httpapi", "internal/repository", "httpapi-translates-only"},
		{"non-app naming a backend", "internal/repository", "internal/storage/consul", "only-app-knows-backends"},
		{"something importing app", "internal/httpapi", "internal/app", "app-is-a-place-not-a-layer"},
		{"crypto learning the domain", "internal/cryptography", "internal/system", "leaves-stay-leaves"},
		{"config growing dependencies", "internal/config", "internal/secrets", "leaves-stay-leaves"},
		{"backend reaching up", "internal/storage/bolt", "internal/cryptography", "backends-see-only-bytes"},
		{"domain subpackage into repository subpackage", "internal/system/foo", "internal/repository/index", "domain-no-infrastructure"},
		{"http into a barrier subpackage", "internal/httpapi", "internal/barrier/x", "httpapi-translates-only"},
		{"crypto subpackage learning the domain", "internal/cryptography/codec", "internal/system", "leaves-stay-leaves"},

		{"app naming a backend", "internal/app", "internal/storage/postgres", ""},
		{"domain on domain", "internal/secrets", "internal/authorization", ""},
		{"repository on domain", "internal/repository", "internal/secrets", ""},
		{"barrier on the storage contract", "internal/barrier", "internal/storage", ""},
		{"backend on the storage contract", "internal/storage/bolt", "internal/storage", ""},
		{"crypto subpackage on its own root", "internal/cryptography/codec", "internal/cryptography", ""},
		{"main on app", "cmd/seal-gate", "internal/app", ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ""
			for _, rule := range Rules {
				if rule.Bad(tc.from, tc.to) {
					got = rule.ID
					break
				}
			}

			if got != tc.want {
				t.Errorf("%s -> %s: got %q, want %q", tc.from, tc.to, got, tc.want)
			}
		})
	}
}
