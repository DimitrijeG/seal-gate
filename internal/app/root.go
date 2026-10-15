package app

import "github.com/dimitrijegasic/seal-gate/internal/identity"

// rootCheckerFunc adapts a function to identity.RootChecker, so the token service can be built before the system
// service it asks.
type rootCheckerFunc func(token []byte) bool

var _ identity.RootChecker = rootCheckerFunc(nil)

func (f rootCheckerFunc) IsRoot(token []byte) bool {
	return f(token)
}
