package authorization

import "slices"

// Principal is who an access decision is made for: the root, or a set of policy names. The zero value grants nothing.
type Principal struct {
	root     bool
	policies []string
}

// NewRootPrincipal returns the principal that passes every check without reading a policy.
func NewRootPrincipal() Principal {
	return Principal{root: true}
}

// NewPolicyPrincipal returns a principal granted what the named policies grant; it keeps its own copy of names.
func NewPolicyPrincipal(names ...string) Principal {
	return Principal{policies: slices.Clone(names)}
}
