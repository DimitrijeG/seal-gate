package system

import "errors"

var (
	ErrAlreadyInitialized   = errors.New("system: already initialized")
	ErrNotInitialized       = errors.New("system: not initialized")
	ErrSealed               = errors.New("system: sealed")
	ErrInvalidShare         = errors.New("system: invalid unseal share")
	ErrInvalidSealConfig    = errors.New("system: invalid seal configuration")
	ErrUnsupportedKeyFormat = errors.New("system: unsupported wrapped key format")
)
