package system

import "errors"

var (
	ErrAlreadyInitialized = errors.New("system: already initialized")
	ErrNotInitialized     = errors.New("system: not initialized")
	ErrAlreadyUnsealed    = errors.New("system: already unsealed")
	ErrInvalidShare       = errors.New("system: invalid unseal share")
	ErrDuplicateShare     = errors.New("system: share already submitted")
	ErrInvalidSealConfig  = errors.New("system: invalid seal configuration")
	// ErrUnreadableRecord covers a record that will not decode and one carrying
	// a version this build has no layout for.
	ErrUnreadableRecord = errors.New("system: unreadable initialization record")
)
