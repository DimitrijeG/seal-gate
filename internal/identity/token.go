package identity

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/dimitrijegasic/seal-gate/internal/authorization"
)

// TokenRepository stores token hashes against entity IDs; it never sees a token. Get returns ErrInvalidToken
// for a missing hash and ErrUnreadableToken for a corrupt record; both methods return ErrSealed while sealed.
type TokenRepository interface {
	Put(ctx context.Context, hash [sha256.Size]byte, entityID string) error
	Get(ctx context.Context, hash [sha256.Size]byte) (string, error)
}

// TokenService issues tokens to entities and resolves them back; it stores only their hashes.
type TokenService struct {
	tokens TokenRepository
	// The service, not the repository: a token's entity is validated on read, as getEntity does.
	entities   *EntityService
	random     Random
	authorizer authorization.Authorizer
}

// NewTokenService returns a TokenService over tokens, checking each token's entity through entities and asking authorizer before issuing.
func NewTokenService(tokens TokenRepository, entities *EntityService, random Random, authorizer authorization.Authorizer) *TokenService {
	return &TokenService{tokens: tokens, entities: entities, random: random, authorizer: authorizer}
}

// CreateToken issues a token for the entity with id if principal may create its tokens; only its hash is stored, so the caller must clear it once delivered.
func (s *TokenService) CreateToken(ctx context.Context, principal authorization.Principal, entityID string) ([]byte, error) {
	if !validID(entityID) {
		return nil, ErrInvalidEntityID
	}
	if err := s.authorizer.Authorize(ctx, principal, entitiesResource+"/"+entityID+"/tokens", authorization.CapabilityCreate); err != nil {
		return nil, fmt.Errorf("identity: %w", err)
	}

	_, err := s.entities.getEntity(ctx, entityID)
	if err != nil {
		return nil, err
	}

	token, err := s.random.Bytes(tokenBytes)
	if err != nil {
		return nil, fmt.Errorf("identity: %w", err)
	}

	err = s.tokens.Put(ctx, sha256.Sum256(token), entityID)
	if err != nil {
		// Never returned, so no caller can clear it.
		clear(token)
		if !ours(err) {
			return nil, fmt.Errorf("identity: %w", err)
		}
		return nil, err
	}
	return token, nil
}

// Resolve returns the entity a token authenticates as; a missing, unknown or orphaned token is ErrInvalidToken alike.
func (s *TokenService) Resolve(ctx context.Context, token []byte) (Entity, error) {
	if len(token) != tokenBytes {
		return Entity{}, ErrInvalidToken
	}

	entityID, err := s.tokens.Get(ctx, sha256.Sum256(token))
	if err != nil && !ours(err) {
		return Entity{}, fmt.Errorf("identity: %w", err)
	}
	if err != nil {
		return Entity{}, err
	}
	// Checked here, not in getEntity: a bad stored ID is a corrupt record, not the caller's mistake.
	if !validID(entityID) {
		return Entity{}, ErrUnreadableToken
	}

	entity, err := s.entities.getEntity(ctx, entityID)
	if errors.Is(err, ErrEntityNotFound) {
		return Entity{}, ErrInvalidToken
	}
	if err != nil {
		return Entity{}, err
	}
	return entity, nil
}
