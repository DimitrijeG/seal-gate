package main

import (
	"fmt"
	"slices"
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

// domainPackages must stay free of infrastructure. Subpackages inherit.
var domainPackages = map[string]bool{
	"internal/system":        true,
	"internal/identity":      true,
	"internal/authorization": true,
	"internal/secrets":       true,
	"internal/lifecycle":     true,
}

// infrastructurePackages is explicit so a new top-level package fails a test
// instead of silently defaulting to infrastructure.
var infrastructurePackages = map[string]bool{
	"internal/cryptography": true,
	"internal/barrier":      true,
	"internal/repository":   true,
	"internal/storage":      true,
	"internal/audit":        true,
}

// topLevel reduces internal/storage/bolt to internal/storage.
func topLevel(rel string) string {
	parts := strings.SplitN(rel, "/", 3)
	if len(parts) < 2 {
		return rel
	}
	return parts[0] + "/" + parts[1]
}

func isDomain(rel string) bool {
	return domainPackages[topLevel(rel)]
}

func categorize(rel string) string {
	switch {
	case strings.HasPrefix(rel, "cmd/"):
		return CatEntrypoint
	case rel == "internal/app":
		return CatComposition
	case rel == "internal/httpapi":
		return CatInterface
	case isDomain(rel):
		return CatDomain
	case rel == "internal/config":
		return CatSupport
	default:
		return CatInfrastructure
	}
}

// classified reports whether rel's category was chosen rather than defaulted.
func classified(rel string) bool {
	return categorize(rel) != CatInfrastructure || infrastructurePackages[topLevel(rel)]
}

// isPersistence reports whether rel is off limits to domain modules and httpapi.
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

// isBackend is true for concrete backends, not the storage contract itself.
func isBackend(rel string) bool {
	return strings.HasPrefix(rel, "internal/storage/")
}

func isLeaf(rel string) bool {
	switch rel {
	case "internal/config", "internal/cryptography", "internal/storage":
		return true
	default:
		return false
	}
}

// Violation is one broken architecture rule.
type Violation struct {
	Rule string `json:"rule"`
	From string `json:"from"`
	To   string `json:"to"`
	Why  string `json:"why"`
}

// Rule is a predicate over one import edge, in module-relative paths.
type Rule struct {
	ID  string
	Why string
	Bad func(from, to string) bool
}

// Rules are checked in order; an edge reports only the first it breaks.
var Rules = []Rule{
	{
		ID:  "domain-no-infrastructure",
		Why: "a domain module must not reach past its own repository interface into persistence or crypto",
		Bad: func(from, to string) bool { return isDomain(from) && isPersistence(to) },
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
		ID:  "app-is-a-place-not-a-layer",
		Why: "nothing imports the composition root except main",
		Bad: func(from, to string) bool { return to == "internal/app" && !strings.HasPrefix(from, "cmd/") },
	},
	{
		ID:  "leaves-stay-leaves",
		Why: "config, cryptography and the storage contract are shared by many packages and must not depend on any of them",
		Bad: func(from, to string) bool { return isLeaf(from) && strings.HasPrefix(to, "internal/") },
	},
	{
		ID:  "backends-see-only-bytes",
		Why: "a storage backend implements the key-value contract and must not know about anything above it",
		Bad: func(from, to string) bool { return isBackend(from) && to != "internal/storage" },
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

// cycles duplicates a compiler check so CI names the cycle in the same report
// as every other rule, even over a tree that does not build.
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
				// The stack runs from the DFS root; the cycle starts where next is.
				loop := labels(stack[slices.Index(stack, next):], rel)
				found = append(found, Violation{
					Rule: "no-import-cycles",
					From: rel[node],
					To:   rel[next],
					Why:  fmt.Sprintf("cycle: %s -> %s", strings.Join(loop, " -> "), rel[next]),
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
