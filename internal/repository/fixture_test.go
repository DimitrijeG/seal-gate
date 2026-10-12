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

	cipher, err := cryptography.NewAEADCipher("aes-256-gcm")
	if err != nil {
		t.Fatalf("NewAEADCipher: %v", err)
	}

	backend := memory.New()
	encrypted := barrier.NewAEADBarrier(backend, keys, cipher)
	return barrierFixture{
		set:       repository.NewSet(backend, encrypted),
		backend:   backend,
		encrypted: encrypted,
		keys:      keys,
	}
}
