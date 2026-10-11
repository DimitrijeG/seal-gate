package secret

import "errors"

var (
	ErrNotFound = errors.New("secret: not found")
	// ErrInvalidPath reports a path or list prefix that breaks the path rule.
	ErrInvalidPath   = errors.New("secret: invalid path")
	ErrValueTooLarge = errors.New("secret: value too large")
	ErrSealed        = errors.New("secret: sealed")
)
