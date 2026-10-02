package repository

import (
	"context"
	"errors"

	"github.com/dimitrijegasic/seal-gate/internal/barrier"
	"github.com/dimitrijegasic/seal-gate/internal/system"
)

var errNotImplemented = errors.New("repository: not implemented")

var _ system.Repository = (*systemRepository)(nil)

type systemRepository struct {
	barrier *barrier.AEADBarrier
}

func (s *systemRepository) IsInitialized(ctx context.Context) (bool, error) {
	return false, errNotImplemented
}

func (s *systemRepository) LoadEncryptedKey(ctx context.Context) (system.EncryptedKey, error) {
	return system.EncryptedKey{}, errNotImplemented
}

func (s *systemRepository) LoadSealConfiguration(ctx context.Context) (system.SealConfiguration, error) {
	return system.SealConfiguration{}, errNotImplemented
}

func (s *systemRepository) SaveInitialization(ctx context.Context, state system.InitializationState) error {
	return errNotImplemented
}
