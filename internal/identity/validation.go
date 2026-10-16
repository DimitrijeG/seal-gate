package identity

import (
	"encoding/hex"

	"github.com/dimitrijegasic/seal-gate/internal/authorization"
)

const (
	idBytes    = 16
	tokenBytes = 32

	maxUsernameLength = 128
	// Long enough for any passphrase; bounds what a request may make the server hold and hash.
	maxPasswordLength = 1024
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

// validateGroup leaves out the ID, as validateLists does.
func validateGroup(group Group) error {
	for _, policy := range group.Policies {
		if !authorization.ValidPolicyName(policy) {
			return ErrInvalidPolicyName
		}
	}
	return nil
}

// validUsername allows lowercase only, so two users cannot differ by case alone.
func validUsername(name string) bool {
	if name == "" || len(name) > maxUsernameLength || name == "." || name == ".." {
		return false
	}
	for i := 0; i < len(name); i++ {
		if !validUsernameByte(name[i]) {
			return false
		}
	}
	return true
}

func validUsernameByte(b byte) bool {
	return (b >= 'a' && b <= 'z') ||
		(b >= '0' && b <= '9') ||
		b == '.' || b == '_' || b == '-'
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
