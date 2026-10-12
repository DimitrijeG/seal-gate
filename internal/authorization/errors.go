package authorization

import "errors"

var (
	ErrNotFound = errors.New("authorization: not found")
	// ErrInvalidName reports a policy name that is not one segment of [A-Za-z0-9._-], at most 128 bytes.
	ErrInvalidName = errors.New("authorization: invalid name")
	// ErrInvalidRule reports a rule with a bad path pattern, or no or an unknown capability.
	ErrInvalidRule = errors.New("authorization: invalid rule")
	ErrSealed      = errors.New("authorization: sealed")
	ErrDenied      = errors.New("authorization: denied")
)
