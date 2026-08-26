package main

import (
	"fmt"
	"sort"
	"strings"
)

// Categories, used for colour and for the collapsed view.
const (
	CatEntrypoint     = "entrypoint"
	CatComposition    = "composition"
	CatInterface      = "interface"
	CatDomain         = "domain"
	CatInfrastructure = "infrastructure"
	CatSupport        = "support"
)

// domainPackages are the modules that must stay free of infrastructure.
var domainPackages = map[string]bool{
	"internal/system":        true,
	"internal/identity":      true,
	"internal/authorization": true,
	"internal/secrets":       true,
	"internal/lifecycle":     true,
}

func categorize(rel string) string {
	switch {
	case strings.HasPrefix(rel, "cmd/"):
		return CatEntrypoint
	case rel == "internal/app":
		return CatComposition
	case rel == "internal/httpapi":
		return CatInterface
	case domainPackages[rel]:
		return CatDomain
	case rel == "internal/common" || rel == "internal/config":
		return CatSupport
	default:
		return CatInfrastructure
	}
}

// isPersistence reports whether rel is a package a domain module or the HTTP
// layer must not reach into directly.
func isPersistence(rel string) bool {
	switch {
	case rel == "internal/repository", rel == "internal/barrier":
		return true
	case strings.HasPrefix(rel, "internal/storage"):
		return true
	case rel == "internal/cryptography":
		return true
	default:
		return false
	}
}

// isBackend reports whether rel is a concrete storage backend, as opposed to
// the storage contract itself.
func isBackend(rel string) bool {
	return strings.HasPrefix(rel, "internal/storage/")
}

// Violation is one broken architecture rule.
type Violation struct {
	Rule string `json:"rule"`
	From string `json:"from"`
	To   string `json:"to"`
	Why  string `json:"why"`
}

// Rule is a predicate over one import edge, stated in terms of paths relative
// to the module root.
type Rule struct {
	ID  string
	Why string
	Bad func(from, to string) bool
}

// Rules are the dependency constraints the module is built around. They are
// the reason this tool is worth more than a picture: each one is also
// assertable in CI (see rules_test.go).
var Rules = []Rule{
	{
		ID:  "domain-no-infrastructure",
		Why: "a domain module must not reach past its own repository interface into persistence or crypto",
		Bad: func(from, to string) bool { return domainPackages[from] && isPersistence(to) },
	},
	{
		ID:  "only-app-knows-backends",
		Why: "app is the composition root and the only package allowed to name a concrete backend",
		Bad: func(from, to string) bool { return isBackend(to) && from != "internal/app" },
	},
	{
		ID:  "httpapi-translates-only",
		Why: "the HTTP layer performs protocol translation and must not query storage or encrypt",
		Bad: func(from, to string) bool { return from == "internal/httpapi" && isPersistence(to) },
	},
	{
		ID:  "common-stays-small",
		Why: "common must not accumulate dependencies on the rest of the module",
		Bad: func(from, to string) bool { return from == "internal/common" && strings.HasPrefix(to, "internal/") },
	},
	{
		ID:  "app-is-a-place-not-a-layer",
		Why: "nothing imports the composition root except main",
		Bad: func(from, to string) bool { return to == "internal/app" && !strings.HasPrefix(from, "cmd/") },
	},
}

// Apply marks every violating edge in place and collects the violations.
func Apply(g *Graph) {
	rel := make(map[string]string, len(g.Nodes))
	for _, node := range g.Nodes {
		rel[node.ID] = node.Rel
	}

	for i := range g.Edges {
		from, to := rel[g.Edges[i].From], rel[g.Edges[i].To]

		for _, rule := range Rules {
			if !rule.Bad(from, to) {
				continue
			}

			g.Edges[i].Rule = rule.ID
			g.Violations = append(g.Violations, Violation{
				Rule: rule.ID,
				From: from,
				To:   to,
				Why:  rule.Why,
			})
			break
		}
	}

	g.Violations = append(g.Violations, cycles(g, rel)...)

	sort.Slice(g.Violations, func(i, j int) bool {
		if g.Violations[i].Rule != g.Violations[j].Rule {
			return g.Violations[i].Rule < g.Violations[j].Rule
		}
		return g.Violations[i].From < g.Violations[j].From
	})
}

// cycles reports import cycles.
//
// Go's compiler already rejects these, so a hit here means the graph was built
// from a tree that does not compile. It is kept because the same check runs in
// CI over a proposed refactor, where catching it early is cheaper.
func cycles(g *Graph, rel map[string]string) []Violation {
	adjacency := make(map[string][]string)
	for _, edge := range g.Edges {
		adjacency[edge.From] = append(adjacency[edge.From], edge.To)
	}

	const (
		white = 0
		grey  = 1
		black = 2
	)

	colour := make(map[string]int)
	var found []Violation

	var visit func(node string, stack []string)
	visit = func(node string, stack []string) {
		colour[node] = grey
		stack = append(stack, node)

		for _, next := range adjacency[node] {
			switch colour[next] {
			case white:
				visit(next, stack)
			case grey:
				found = append(found, Violation{
					Rule: "no-import-cycles",
					From: rel[node],
					To:   rel[next],
					Why:  fmt.Sprintf("cycle: %s -> %s", strings.Join(labels(stack, rel), " -> "), rel[next]),
				})
			}
		}

		colour[node] = black
	}

	for _, node := range g.Nodes {
		if colour[node.ID] == white {
			visit(node.ID, nil)
		}
	}

	return found
}

func labels(ids []string, rel map[string]string) []string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = rel[id]
	}
	return out
}
