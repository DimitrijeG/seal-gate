// Package identity owns who is asking: entities, the policies and groups they hold, and the tokens that authenticate as them.
package identity

import "time"

// Clock is the time tokens are issued and checked against, so tests can fix it.
type Clock interface {
	Now() time.Time
}

// Random is the source of generated IDs and tokens.
type Random interface {
	Bytes(n int) ([]byte, error)
}
