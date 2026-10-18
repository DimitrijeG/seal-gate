package repository_test

import (
	"testing"

	"github.com/dimitrijegasic/seal-gate/internal/barrier"
	"github.com/dimitrijegasic/seal-gate/internal/cryptography"
	"github.com/dimitrijegasic/seal-gate/internal/repository"
	"github.com/dimitrijegasic/seal-gate/internal/storage"
	"github.com/dimitrijegasic/seal-gate/internal/storage/memory"
)

// barrierFixture holds the repositories with the raw backend and the barrier beneath them.
type barrierFixture struct {
	set       *repository.Set
	backend   storage.Backend
	encrypted *barrier.AEADBarrier
	keys      *cryptography.KeyHolder
	cipher    *recordingCipher
}

// recordingCipher keeps the plaintexts it handles as given, so a test can check they were cleared.
type recordingCipher struct {
	cryptography.Cipher
	encrypted []byte // the last plaintext Encrypt was given
	decrypted []byte // the last plaintext Decrypt returned
}

func (c *recordingCipher) Encrypt(key, plaintext, additionalData []byte) ([]byte, error) {
	c.encrypted = plaintext
	return c.Cipher.Encrypt(key, plaintext, additionalData)
}

func (c *recordingCipher) Decrypt(key, ciphertext, additionalData []byte) ([]byte, error) {
	plaintext, err := c.Cipher.Decrypt(key, ciphertext, additionalData)
	c.decrypted = plaintext
	return plaintext, err
}

func newBarrierFixture(t *testing.T) barrierFixture {
	t.Helper()

	key, err := cryptography.CryptoRandom{}.Bytes(32)
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}
	keys := cryptography.NewKeyHolder()
	if err := keys.Install(key); err != nil {
		t.Fatalf("Install: %v", err)
	}

	aead, err := cryptography.NewAEADCipher("aes-256-gcm")
	if err != nil {
		t.Fatalf("NewAEADCipher: %v", err)
	}
	cipher := &recordingCipher{Cipher: aead}

	backend := memory.New()
	encrypted := barrier.NewAEADBarrier(backend, keys, cipher)
	return barrierFixture{
		set:       repository.NewSet(backend, encrypted),
		backend:   backend,
		encrypted: encrypted,
		keys:      keys,
		cipher:    cipher,
	}
}
