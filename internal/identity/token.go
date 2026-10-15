package identity

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/dimitrijegasic/seal-gate/internal/authorization"
)

// StoredToken is what is kept against a token's hash; the token is refused from ExpiresAt on.
type StoredToken struct {
	EntityID  string
	ExpiresAt time.Time
}

// TokenRepository stores tokens by their hashes; it never sees a token. Get returns ErrInvalidToken
// for a missing hash and ErrUnreadableToken for a corrupt record; both methods return ErrSealed while sealed.
type TokenRepository interface {
	Put(ctx context.Context, hash [sha256.Size]byte, stored StoredToken) error
	Get(ctx context.Context, hash [sha256.Size]byte) (StoredToken, error)
}

// TokenService issues tokens to entities and resolves them back; it stores only their hashes.
type TokenService struct {
	tokens TokenRepository
	// The service, not the repository: a token's entity is validated on read, as getEntity does.
	entities   *EntityService
	random     Random
	authorizer authorization.Authorizer
	clock      Clock
	ttl        time.Duration
}

// NewTokenService returns a TokenService over tokens that issues each token to live ttl from clock's time, checking its entity through entities and asking authorizer first.
func NewTokenService(tokens TokenRepository, entities *EntityService, random Random, authorizer authorization.Authorizer, clock Clock, ttl time.Duration) *TokenService {
	return &TokenService{tokens: tokens, entities: entities, random: random, authorizer: authorizer, clock: clock, ttl: ttl}
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

	err = s.tokens.Put(ctx, sha256.Sum256(token), StoredToken{EntityID: entityID, ExpiresAt: s.clock.Now().Add(s.ttl)})
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

// Resolve returns the entity a token authenticates as; a missing, unknown, expired or orphaned token is ErrInvalidToken alike.
func (s *TokenService) Resolve(ctx context.Context, token []byte) (Entity, error) {
	if len(token) != tokenBytes {
		return Entity{}, ErrInvalidToken
	}

	stored, err := s.tokens.Get(ctx, sha256.Sum256(token))
	if err != nil && !ours(err) {
		return Entity{}, fmt.Errorf("identity: %w", err)
	}
	if err != nil {
		return Entity{}, err
	}
	// Checked here, not in getEntity: a bad stored ID is a corrupt record, not the caller's mistake.
	if !validID(stored.EntityID) {
		return Entity{}, ErrUnreadableToken
	}
	if !s.clock.Now().Before(stored.ExpiresAt) {
		return Entity{}, ErrInvalidToken
	}

	entity, err := s.entities.getEntity(ctx, stored.EntityID)
	if errors.Is(err, ErrEntityNotFound) {
		return Entity{}, ErrInvalidToken
	}
	if err != nil {
		return Entity{}, err
	}
	return entity, nil
}
