package identity

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/dimitrijegasic/seal-gate/internal/authorization"
)

// StoredToken is what is kept against a token's hash; the token is refused from ExpiresAt on.
type StoredToken struct {
	EntityID  string
	ExpiresAt time.Time
}

func (t StoredToken) expired(now time.Time) bool {
	return !now.Before(t.ExpiresAt)
}

// TokenRepository stores tokens by their hashes; it never sees a token. Get returns ErrInvalidToken
// for a missing hash and ErrUnreadableToken for a corrupt record; Delete of a missing hash is nil; every method
// returns ErrSealed while sealed.
type TokenRepository interface {
	Put(ctx context.Context, hash [sha256.Size]byte, stored StoredToken) error
	Get(ctx context.Context, hash [sha256.Size]byte) (StoredToken, error)
	Delete(ctx context.Context, hash [sha256.Size]byte) error
	List(ctx context.Context) ([][sha256.Size]byte, error)
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
	// Serialises rotations, so two of one token cannot both find it live and each issue a successor.
	mu sync.Mutex
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

	return s.issue(ctx, entityID, ttl)
}

// issue stores a new token for entityID, living ttl or the default if zero; on failure the token is cleared.
func (s *TokenService) issue(ctx context.Context, entityID string, ttl time.Duration) ([]byte, time.Time, error) {
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

// RotateToken replaces token with a new one for its entity, living ttl or the default if zero; on failure token still works.
// The root token is ErrRootToken, and an expired or unknown one ErrInvalidToken.
func (s *TokenService) RotateToken(ctx context.Context, token []byte, ttl time.Duration) ([]byte, time.Time, error) {
	if ttl < 0 || ttl > s.ttl.Max {
		return nil, time.Time{}, ErrInvalidTTL
	}
	if s.root.IsRoot(token) {
		return nil, time.Time{}, ErrRootToken
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	entity, err := s.Resolve(ctx, token)
	if err != nil {
		return nil, time.Time{}, err
	}

	// Stored before the old one is deleted, so a failure between leaves the caller a working token.
	rotated, expiresAt, err := s.issue(ctx, entity.ID, ttl)
	if err != nil {
		return nil, time.Time{}, err
	}

	err = s.tokens.Delete(ctx, sha256.Sum256(token))
	if err != nil {
		// Best effort, its error dropped: the caller keeps the old token to retry with, which beats two live ones.
		_ = s.tokens.Delete(context.WithoutCancel(ctx), sha256.Sum256(rotated))
		clear(rotated)
		if !ours(err) {
			return nil, time.Time{}, fmt.Errorf("identity: %w", err)
		}
		return nil, time.Time{}, err
	}
	return rotated, expiresAt, nil
}

// PurgeExpired deletes every token expired at the clock's time, calling report once per token deleted. A failed token
// does not stop it: failures return joined, except ErrSealed and a cancelled ctx, which end it at once.
func (s *TokenService) PurgeExpired(ctx context.Context, report func()) error {
	now := s.clock.Now()
	hashes, err := s.tokens.List(ctx)
	switch {
	case err != nil && !ours(err):
		return fmt.Errorf("identity: %w", err)
	case err != nil:
		return err
	}

	var failures []error
	for _, hash := range hashes {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("identity: %w", err)
		}
		purged, err := s.purgeToken(ctx, hash, now)
		if errors.Is(err, ErrSealed) {
			return err
		}
		if err != nil {
			failures = append(failures, err)
			continue
		}
		if purged {
			report()
		}
	}
	return errors.Join(failures...)
}

// purgeToken deletes the token stored under hash if it expired by now, reporting whether it did; one gone since List is skipped.
func (s *TokenService) purgeToken(ctx context.Context, hash [sha256.Size]byte, now time.Time) (bool, error) {
	stored, err := s.tokens.Get(ctx, hash)
	switch {
	case errors.Is(err, ErrInvalidToken):
		return false, nil
	case err != nil && !ours(err):
		return false, fmt.Errorf("identity: %w", err)
	case err != nil:
		return false, err
	}
	if !stored.expired(now) {
		return false, nil
	}

	err = s.tokens.Delete(ctx, hash)
	switch {
	case err != nil && !ours(err):
		return false, fmt.Errorf("identity: %w", err)
	case err != nil:
		return false, err
	}
	return true, nil
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
	if stored.expired(s.clock.Now()) {
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
