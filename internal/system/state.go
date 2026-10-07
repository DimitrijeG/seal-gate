package system

import (
	"time"
)

type SealConfiguration struct {
	Shares    int
	Threshold int
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
