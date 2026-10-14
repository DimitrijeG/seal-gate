package app

import (
	"errors"
	"testing"

	"github.com/dimitrijegasic/seal-gate/internal/config"
	"github.com/dimitrijegasic/seal-gate/internal/cryptography"
	"github.com/dimitrijegasic/seal-gate/internal/secret"
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
		entry := secret.Entry{Value: []byte("secret")}

		if err := repo.Put(t.Context(), "db/password", entry); !errors.Is(err, secret.ErrSealed) {
			t.Fatalf("Put before Install: got %v, want %v", err, secret.ErrSealed)
		}
		key, err := cryptography.CryptoRandom{}.Bytes(32)
		if err != nil {
			t.Fatalf("Bytes: %v", err)
		}
		if err := infra.keys.Install(key); err != nil {
			t.Fatalf("Install: %v", err)
		}

		if err := repo.Put(t.Context(), "db/password", entry); err != nil {
			t.Errorf("Put after Install: %v", err)
		}
	})
}
