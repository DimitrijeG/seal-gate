package app

import (
	"errors"
	"testing"

	"github.com/dimitrijegasic/seal-gate/internal/barrier"
	"github.com/dimitrijegasic/seal-gate/internal/config"
	"github.com/dimitrijegasic/seal-gate/internal/cryptography"
	"github.com/dimitrijegasic/seal-gate/internal/storage/memory"
)

func TestRepositories(t *testing.T) {
	t.Run("the secrets repository opens once the shared key holder has a key", func(t *testing.T) {
		infra, err := buildInfrastructure(&config.Config{
			Logger: config.LoggerConfig{Level: "error", Format: "text"},
			Crypto: config.CryptoConfig{AEADAlgorithm: "aes-256-gcm"},
		})
		if err != nil {
			t.Fatalf("buildInfrastructure: %v", err)
		}
		repo := buildRepositories(memory.New(), infra).set.Secret
		value := []byte("secret")

		if err := repo.Put(t.Context(), "db/password", value); !errors.Is(err, barrier.ErrSealed) {
			t.Fatalf("Put before Install: got %v, want %v", err, barrier.ErrSealed)
		}
		key, err := cryptography.CryptoRandom{}.Bytes(32)
		if err != nil {
			t.Fatalf("Bytes: %v", err)
		}
		if err := infra.keys.Install(key); err != nil {
			t.Fatalf("Install: %v", err)
		}

		if err := repo.Put(t.Context(), "db/password", value); err != nil {
			t.Errorf("Put after Install: %v", err)
		}
	})
}
