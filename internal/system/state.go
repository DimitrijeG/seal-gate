package system

import (
	"fmt"
	"time"
)

type SealConfiguration struct {
	Shares    int
	Threshold int
}

// wrapFormatVersion is stored with the wrapped key so a format change is
// detected rather than fed to the wrong unwrap.
const wrapFormatVersion = 1

// wrapAdditionalData binds the ciphertext to its purpose and format version,
// which are otherwise stored unauthenticated.
func wrapAdditionalData(version int) []byte {
	return fmt.Appendf(nil, "seal-gate/barrier-key/v%d", version)
}

type EncryptedKey struct {
	Ciphertext []byte
	Version    int
}

type InitializationState struct {
	Config        SealConfiguration
	EncryptedKey  EncryptedKey
	InitializedAt time.Time
}
