// Package identity owns who is asking: entities, the policies and groups they hold, and the tokens that authenticate as them.
package identity

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
)

// EntityRepository stores entities by ID. Get returns ErrEntityNotFound for a missing ID and ErrUnreadableEntity
// for a corrupt record; Delete does not fail on a missing ID; every method returns ErrSealed while sealed.
type EntityRepository interface {
	Put(ctx context.Context, entity Entity) error
	Get(ctx context.Context, id string) (Entity, error)
	Delete(ctx context.Context, id string) error
}

// TokenRepository stores token hashes against entity IDs; it never sees a token. Get returns ErrInvalidToken
// for a missing hash and ErrUnreadableToken for a corrupt record; both methods return ErrSealed while sealed.
type TokenRepository interface {
	Put(ctx context.Context, hash [sha256.Size]byte, entityID string) error
	Get(ctx context.Context, hash [sha256.Size]byte) (string, error)
}

// GroupRepository stores groups by ID. Get returns ErrGroupNotFound for a missing ID and ErrUnreadableGroup
// for a corrupt record; Delete does not fail on a missing ID; every method returns ErrSealed while sealed.
type GroupRepository interface {
	Put(ctx context.Context, group Group) error
	Get(ctx context.Context, id string) (Group, error)
	Delete(ctx context.Context, id string) error
}

// Random is the source of generated IDs and tokens.
type Random interface {
	Bytes(n int) ([]byte, error)
}

// Service manages entities, groups and the tokens issued to entities, validating each before it reaches a repository.
type Service struct {
	// Held by update and delete of entities and groups, so no delete lands between an update's check and its write
	// and brings one back with its tokens or grants. Process-local: it assumes one instance.
	mu       sync.Mutex
	entities EntityRepository
	tokens   TokenRepository
	groups   GroupRepository
	random   Random
}

// New returns a Service over entities, tokens and groups, taking IDs and tokens from random.
func New(entities EntityRepository, tokens TokenRepository, groups GroupRepository, random Random) *Service {
	return &Service{entities: entities, tokens: tokens, groups: groups, random: random}
}

// CreateToken issues a token for the entity with id; only its hash is stored, so the caller must clear it once delivered.
func (s *Service) CreateToken(ctx context.Context, entityID string) ([]byte, error) {
	_, err := s.GetEntity(ctx, entityID)
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
func (s *Service) Resolve(ctx context.Context, token []byte) (Entity, error) {
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
	// Checked here, not in GetEntity: a bad stored ID is a corrupt record, not the caller's mistake.
	if !validID(entityID) {
		return Entity{}, ErrUnreadableToken
	}

	entity, err := s.GetEntity(ctx, entityID)
	if errors.Is(err, ErrEntityNotFound) {
		return Entity{}, ErrInvalidToken
	}
	if err != nil {
		return Entity{}, err
	}
	return entity, nil
}

// CreateEntity stores entity under a newly generated ID, replacing any ID it carries, and returns that ID.
func (s *Service) CreateEntity(ctx context.Context, entity Entity) (string, error) {
	if err := validateLists(entity); err != nil {
		return "", err
	}

	id, err := s.random.Bytes(idBytes)
	if err != nil {
		return "", fmt.Errorf("identity: %w", err)
	}
	entity.ID = hex.EncodeToString(id)

	err = s.entities.Put(ctx, entity)
	if err != nil && !ours(err) {
		return "", fmt.Errorf("identity: %w", err)
	}
	if err != nil {
		return "", err
	}
	return entity.ID, nil
}

// GetEntity returns the entity with id; ErrEntityNotFound if there is none, ErrUnreadableEntity if its record is invalid.
func (s *Service) GetEntity(ctx context.Context, id string) (Entity, error) {
	if !validID(id) {
		return Entity{}, ErrInvalidEntityID
	}

	entity, err := s.entities.Get(ctx, id)
	if err != nil && !ours(err) {
		return Entity{}, fmt.Errorf("identity: %w", err)
	}
	if err != nil {
		return Entity{}, err
	}
	// Checked again on read: an invalid stored name would change what the entity is granted.
	if validateLists(entity) != nil {
		return Entity{}, ErrUnreadableEntity
	}
	return entity, nil
}

// DeleteEntity removes the entity with id; a missing ID is not an error.
func (s *Service) DeleteEntity(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !validID(id) {
		return ErrInvalidEntityID
	}

	err := s.entities.Delete(ctx, id)
	if err != nil && !ours(err) {
		return fmt.Errorf("identity: %w", err)
	}
	return err
}

// UpdateEntity replaces an existing entity's policies and groups; it never creates one, so a missing ID is ErrEntityNotFound.
func (s *Service) UpdateEntity(ctx context.Context, entity Entity) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !validID(entity.ID) {
		return ErrInvalidEntityID
	}
	if err := validateLists(entity); err != nil {
		return err
	}

	// GetEntity, not the repository: an entity that fails validation on read is not updated either.
	if _, err := s.GetEntity(ctx, entity.ID); err != nil {
		return err
	}

	err := s.entities.Put(ctx, entity)
	if err != nil && !ours(err) {
		return fmt.Errorf("identity: %w", err)
	}
	return err
}

// CreateGroup stores group under a newly generated ID, replacing any ID it carries, and returns that ID.
func (s *Service) CreateGroup(ctx context.Context, group Group) (string, error) {
	if err := validateGroup(group); err != nil {
		return "", err
	}

	id, err := s.random.Bytes(idBytes)
	if err != nil {
		return "", fmt.Errorf("identity: %w", err)
	}
	group.ID = hex.EncodeToString(id)

	err = s.groups.Put(ctx, group)
	if err != nil && !ours(err) {
		return "", fmt.Errorf("identity: %w", err)
	}
	if err != nil {
		return "", err
	}
	return group.ID, nil
}

// GetGroup returns the group with id; ErrGroupNotFound if there is none, ErrUnreadableGroup if its record is invalid.
func (s *Service) GetGroup(ctx context.Context, id string) (Group, error) {
	if !validID(id) {
		return Group{}, ErrInvalidGroupID
	}

	group, err := s.groups.Get(ctx, id)
	if err != nil && !ours(err) {
		return Group{}, fmt.Errorf("identity: %w", err)
	}
	if err != nil {
		return Group{}, err
	}
	// Checked again on read: an invalid stored name would change what the group grants.
	if validateGroup(group) != nil {
		return Group{}, ErrUnreadableGroup
	}
	return group, nil
}

// DeleteGroup removes the group with id; a missing ID is not an error.
func (s *Service) DeleteGroup(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !validID(id) {
		return ErrInvalidGroupID
	}

	err := s.groups.Delete(ctx, id)
	if err != nil && !ours(err) {
		return fmt.Errorf("identity: %w", err)
	}
	return err
}

// UpdateGroup replaces an existing group's policies; it never creates one, so a missing ID is ErrGroupNotFound.
func (s *Service) UpdateGroup(ctx context.Context, group Group) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !validID(group.ID) {
		return ErrInvalidGroupID
	}
	if err := validateGroup(group); err != nil {
		return err
	}

	// GetGroup, not the repository: a group that fails validation on read is not updated either.
	if _, err := s.GetGroup(ctx, group.ID); err != nil {
		return err
	}

	err := s.groups.Put(ctx, group)
	if err != nil && !ours(err) {
		return fmt.Errorf("identity: %w", err)
	}
	return err
}
