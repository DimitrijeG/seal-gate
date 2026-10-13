package identity

import (
	"context"
	"encoding/hex"
	"fmt"
	"sync"
)

// Entity is an identity with its own policies; its ID is generated and never reused, and Groups holds group IDs.
type Entity struct {
	ID       string
	Policies []string
	Groups   []string
}

// EntityRepository stores entities by ID. Get returns ErrEntityNotFound for a missing ID and ErrUnreadableEntity
// for a corrupt record; Delete does not fail on a missing ID; every method returns ErrSealed while sealed.
type EntityRepository interface {
	Put(ctx context.Context, entity Entity) error
	Get(ctx context.Context, id string) (Entity, error)
	Delete(ctx context.Context, id string) error
}

// EntityService manages entities, validating them before they reach the repository.
type EntityService struct {
	// Held by update and delete, so no delete lands between update's existence check and its write
	// and brings a deleted entity back with its tokens. Process-local: it assumes one instance.
	mu       sync.Mutex
	entities EntityRepository
	random   Random
}

// NewEntityService returns an EntityService over entities, taking IDs from random.
func NewEntityService(entities EntityRepository, random Random) *EntityService {
	return &EntityService{entities: entities, random: random}
}

// CreateEntity stores entity under a newly generated ID, replacing any ID it carries, and returns that ID.
func (s *EntityService) CreateEntity(ctx context.Context, entity Entity) (string, error) {
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
func (s *EntityService) GetEntity(ctx context.Context, id string) (Entity, error) {
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
func (s *EntityService) DeleteEntity(ctx context.Context, id string) error {
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
func (s *EntityService) UpdateEntity(ctx context.Context, entity Entity) error {
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
