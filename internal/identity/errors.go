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
	// ErrInvalidToken reports a token that is missing, unknown, expired, or names a deleted entity; callers cannot tell which.
	ErrInvalidToken = errors.New("identity: invalid token")
	// ErrUnreadableToken reports a stored token record that does not decode or names an invalid entity ID.
	ErrUnreadableToken = errors.New("identity: unreadable token")
	ErrGroupNotFound   = errors.New("identity: group not found")
	// ErrInvalidTTL reports a token TTL that is negative or above the configured maximum.
	ErrInvalidTTL = errors.New("identity: invalid TTL")
	// ErrUnreadableGroup reports a stored group that does not decode, or whose policy names are invalid.
	ErrUnreadableGroup = errors.New("identity: unreadable group")
	// ErrRootToken reports a revoke or rotate of the root token, which is never stored and so can be neither.
	ErrRootToken = errors.New("identity: root token cannot be revoked or rotated")
)

// ours reports the sentinels a repository may return, which pass up unwrapped so their prefix is not doubled.
func ours(err error) bool {
	return errors.Is(err, ErrEntityNotFound) ||
		errors.Is(err, ErrUnreadableEntity) ||
		errors.Is(err, ErrSealed) ||
		errors.Is(err, ErrInvalidToken) ||
		errors.Is(err, ErrUnreadableToken) ||
		errors.Is(err, ErrGroupNotFound) ||
		errors.Is(err, ErrUnreadableGroup)
}
