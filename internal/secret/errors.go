package secret

import "errors"

var (
	ErrNotFound = errors.New("secret: not found")
	// ErrInvalidPath reports a path or list prefix that breaks the path rule.
	ErrInvalidPath   = errors.New("secret: invalid path")
	ErrValueTooLarge = errors.New("secret: value too large")
	ErrSealed        = errors.New("secret: sealed")
	ErrExists        = errors.New("secret: already exists")
	ErrInvalidLength = errors.New("secret: invalid length")
	ErrInvalidTTL    = errors.New("secret: invalid TTL")
	// ErrNotRotatable reports a secret seal-gate did not generate, so it does not know the shape to rotate it to.
	ErrNotRotatable = errors.New("secret: not rotatable")
)
