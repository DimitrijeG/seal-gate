package config

import "errors"

var (
	// ErrInvalidFile reports a configuration file the decoder refused: an unknown field, a value of the wrong type, a duration not written as text, or more than one document.
	ErrInvalidFile = errors.New("config: invalid file")
	// ErrMissingField reports a configuration file that leaves a field out; its message names the field.
	ErrMissingField = errors.New("config: missing field")
)
