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
// for a missing hash and ErrUnreadableToken for a corrupt record; Delete of a missing hash is nil; every method
// returns ErrSealed while sealed.
type TokenRepository interface {
	Put(ctx context.Context, hash [sha256.Size]byte, stored StoredToken) error
	Get(ctx context.Context, hash [sha256.Size]byte) (StoredToken, error)
	Delete(ctx context.Context, hash [sha256.Size]byte) error
}

// TokenService issues tokens to entities and resolves them back; it stores only their hashes.
type TokenService struct {
	tokens TokenRepository
	// The service, not the repository: a token's entity is validated on read, as getEntity does.
	entities   *EntityService
	root       RootChecker
	random     Random
	authorizer authorization.Authorizer
	clock      Clock
	ttl        TokenTTL
}

// TokenTTL is how long a token lives when none is asked for, and the longest one may be asked for.
type TokenTTL struct {
	Default time.Duration
	Max     time.Duration
}

// NewTokenService returns a TokenService over tokens that issues each token from clock's time, for ttl's default unless
// asked otherwise, checking its entity through entities and asking authorizer first; root names the token it never stores.
func NewTokenService(tokens TokenRepository, entities *EntityService, root RootChecker, random Random, authorizer authorization.Authorizer, clock Clock, ttl TokenTTL) *TokenService {
	return &TokenService{tokens: tokens, entities: entities, root: root, random: random, authorizer: authorizer, clock: clock, ttl: ttl}
}

// CreateToken issues a token for the entity with id if principal may create its tokens, returning it and its expiry; a
// zero ttl means the default. Only its hash is stored, so the caller must clear the token once delivered.
func (s *TokenService) CreateToken(ctx context.Context, principal authorization.Principal, entityID string, ttl time.Duration) ([]byte, time.Time, error) {
	if !validID(entityID) {
		return nil, time.Time{}, ErrInvalidEntityID
	}
	if ttl < 0 || ttl > s.ttl.Max {
		return nil, time.Time{}, ErrInvalidTTL
	}
	if err := s.authorizer.Authorize(ctx, principal, entitiesResource+"/"+entityID+"/tokens", authorization.CapabilityCreate); err != nil {
		return nil, time.Time{}, fmt.Errorf("identity: %w", err)
	}

	_, err := s.entities.getEntity(ctx, entityID)
	if err != nil {
		return nil, time.Time{}, err
	}

	token, err := s.random.Bytes(tokenBytes)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("identity: %w", err)
	}

	if ttl == 0 {
		ttl = s.ttl.Default
	}
	expiresAt := s.clock.Now().Add(ttl)
	err = s.tokens.Put(ctx, sha256.Sum256(token), StoredToken{EntityID: entityID, ExpiresAt: expiresAt})
	if err != nil {
		// Never returned, so no caller can clear it.
		clear(token)
		if !ours(err) {
			return nil, time.Time{}, fmt.Errorf("identity: %w", err)
		}
		return nil, time.Time{}, err
	}
	return token, expiresAt, nil
}

// RevokeToken deletes token so it no longer resolves; the root token is ErrRootToken, as it is never stored.
func (s *TokenService) RevokeToken(ctx context.Context, token []byte) error {
	if len(token) != tokenBytes {
		return ErrInvalidToken
	}
	if s.root.IsRoot(token) {
		return ErrRootToken
	}

	err := s.tokens.Delete(ctx, sha256.Sum256(token))
	if err != nil && !ours(err) {
		return fmt.Errorf("identity: %w", err)
	}
	return err
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
