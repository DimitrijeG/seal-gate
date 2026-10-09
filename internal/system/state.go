package system

import (
	"time"
)

// SealConfiguration is how many shares init makes and how many unseal needs.
type SealConfiguration struct {
	Shares    int
	Threshold int
}

// EncryptedKey is the barrier key wrapped under the root key;
// Version names the wrap format.
type EncryptedKey struct {
	Ciphertext []byte
	Version    int
}

// InitializationState is everything init persists,
// saved as one record so a crash cannot leave it half-written.
type InitializationState struct {
	Config        SealConfiguration
	EncryptedKey  EncryptedKey
	InitializedAt time.Time
}
