// Package identity owns who is asking: entities, the policies and groups they hold, and the tokens that authenticate as them.
package identity

// Random is the source of generated IDs and tokens.
type Random interface {
	Bytes(n int) ([]byte, error)
}
