package identity

import (
	"encoding/hex"

	"github.com/dimitrijegasic/seal-gate/internal/authorization"
)

const (
	idBytes    = 16
	tokenBytes = 32
)

// validateLists leaves out the ID: create checks the entity before it has one.
func validateLists(entity Entity) error {
	for _, policy := range entity.Policies {
		if !authorization.ValidPolicyName(policy) {
			return ErrInvalidPolicyName
		}
	}
	for _, group := range entity.Groups {
		if !validID(group) {
			return ErrInvalidGroupID
		}
	}
	return nil
}

func validID(id string) bool {
	return len(id) == hex.EncodedLen(idBytes) && validHex(id)
}

func validHex(s string) bool {
	for i := 0; i < len(s); i++ {
		if !validHexByte(s[i]) {
			return false
		}
	}
	return true
}

func validHexByte(b byte) bool {
	return (b >= 'a' && b <= 'f') ||
		(b >= '0' && b <= '9')
}
