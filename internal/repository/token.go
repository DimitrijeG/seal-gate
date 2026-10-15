package repository

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/dimitrijegasic/seal-gate/internal/barrier"
	"github.com/dimitrijegasic/seal-gate/internal/identity"
	"github.com/dimitrijegasic/seal-gate/internal/storage"
)

// tokenRepository stores token hashes through the barrier, one key per hash; it never sees a token.
type tokenRepository struct {
	encrypted *barrier.AEADBarrier
}

var _ identity.TokenRepository = (*tokenRepository)(nil)

const (
	tokenRecordVersion = 2
	// Every barrier key starts with its domain's prefix,
	// never sys/, so no path reaches the system records.
	tokenPrefix = "tokens/"
)

// tokenRecord is the stored layout; it changes only with its version. The hash is the key, not a field.
type tokenRecord struct {
	Version   int       `json:"version"`
	EntityID  string    `json:"entity_id"`
	ExpiresAt time.Time `json:"expires_at"`
}

func tokenKey(hash [sha256.Size]byte) string {
	return tokenPrefix + hex.EncodeToString(hash[:])
}

func (r *tokenRepository) Put(ctx context.Context, hash [sha256.Size]byte, stored identity.StoredToken) error {
	record := tokenRecord{
		Version:   tokenRecordVersion,
		EntityID:  stored.EntityID,
		ExpiresAt: stored.ExpiresAt,
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("repository: %w", err)
	}

	err = r.encrypted.Put(ctx, tokenKey(hash), encoded)
	if errors.Is(err, barrier.ErrSealed) {
		return identity.ErrSealed
	}
	if err != nil {
		return fmt.Errorf("repository: %w", err)
	}
	return nil
}

func (r *tokenRepository) Get(ctx context.Context, hash [sha256.Size]byte) (identity.StoredToken, error) {
	encoded, err := r.encrypted.Get(ctx, tokenKey(hash))
	if errors.Is(err, barrier.ErrSealed) {
		return identity.StoredToken{}, identity.ErrSealed
	}
	if errors.Is(err, storage.ErrNotFound) {
		return identity.StoredToken{}, identity.ErrInvalidToken
	}
	if err != nil {
		return identity.StoredToken{}, fmt.Errorf("repository: %w", err)
	}

	var record tokenRecord
	// The decode error is replaced, not wrapped: as a *json.SyntaxError it would
	// reach the client as a 400 about its own request body.
	if err := json.Unmarshal(encoded, &record); err != nil {
		return identity.StoredToken{}, identity.ErrUnreadableToken
	}
	if record.Version != tokenRecordVersion {
		return identity.StoredToken{}, identity.ErrUnreadableToken
	}
	return identity.StoredToken{EntityID: record.EntityID, ExpiresAt: record.ExpiresAt}, nil
}
