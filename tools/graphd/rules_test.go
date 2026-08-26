package main

import (
	"os"
	"testing"
)

// defaultRepo is where the module under test lives. When this tool moves into
// the repo as tools/graphd, change it to "../..".
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

// TestArchitecture is the same check the server draws in red, run as a test.
// The visualization is for noticing; this is for enforcing.
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

// TestCategoriesCoverEveryPackage guards against a new top-level package
// silently landing in "infrastructure" because nobody classified it.
func TestCategoriesCoverEveryPackage(t *testing.T) {
	graph, err := Load(repoDir(t))
	if err != nil {
		t.Fatalf("load graph: %v", err)
	}

	for _, node := range graph.Nodes {
		if node.Category == CatInfrastructure && domainPackages[node.Rel] {
			t.Errorf("%s is categorized as infrastructure but listed as a domain package", node.Rel)
		}
	}
}

func TestRulePredicates(t *testing.T) {
	cases := []struct {
		name, from, to, want string
	}{
		{"domain reaching into storage", "internal/secrets", "internal/storage/postgres", "domain-no-infrastructure"},
		{"domain reaching into the barrier", "internal/identity", "internal/barrier", "domain-no-infrastructure"},
		{"http querying storage", "internal/httpapi", "internal/repository", "httpapi-translates-only"},
		{"non-app naming a backend", "internal/repository", "internal/storage/consul", "only-app-knows-backends"},
		{"common growing dependencies", "internal/common", "internal/secrets", "common-stays-small"},
		{"something importing app", "internal/httpapi", "internal/app", "app-is-a-place-not-a-layer"},

		{"app naming a backend", "internal/app", "internal/storage/postgres", ""},
		{"domain on domain", "internal/secrets", "internal/authorization", ""},
		{"repository on domain", "internal/repository", "internal/secrets", ""},
		{"barrier on the storage contract", "internal/barrier", "internal/storage", ""},
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
