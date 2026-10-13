package identity

import "errors"

var (
	ErrEntityNotFound = errors.New("identity: entity not found")
	// ErrInvalidEntityID reports an ID that is not 32 lowercase hex characters.
	ErrInvalidEntityID   = errors.New("identity: invalid entity ID")
	ErrInvalidPolicyName = errors.New("identity: invalid policy name")
	// ErrInvalidGroupID reports a group ID that is not 32 lowercase hex characters.
	ErrInvalidGroupID = errors.New("identity: invalid group ID")
	// ErrUnreadableEntity reports a stored entity that does not decode, or whose policies or groups are invalid.
	ErrUnreadableEntity = errors.New("identity: unreadable entity")
	ErrSealed           = errors.New("identity: sealed")
)

// ours reports the sentinels a repository may return, which pass up unwrapped so their prefix is not doubled.
func ours(err error) bool {
	return errors.Is(err, ErrEntityNotFound) || errors.Is(err, ErrSealed) || errors.Is(err, ErrUnreadableEntity)
}
