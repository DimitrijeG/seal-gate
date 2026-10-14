package authorization

import "slices"

// Principal is who an access decision is made for: the root, or an entity and its policy names. The zero value grants nothing.
type Principal struct {
	root     bool
	id       string
	policies []string
}

// NewRootPrincipal returns the principal that passes every check without reading a policy.
func NewRootPrincipal() Principal {
	return Principal{root: true}
}

// NewEntityPrincipal returns the principal of entity id, granted what the named policies grant; it keeps its own copy of policies.
func NewEntityPrincipal(id string, policies ...string) Principal {
	return Principal{id: id, policies: slices.Clone(policies)}
}

const rootIdentity = "root"

// Identity names who p is, for audit: "root", the entity ID, or "" for the zero value. It is never a token.
func (p Principal) Identity() string {
	if p.root {
		return rootIdentity
	}
	return p.id
}
