package identity

import (
	"context"
	"encoding/hex"
	"fmt"
	"sync"

	"github.com/dimitrijegasic/seal-gate/internal/authorization"
)

// Entity is an identity with its own policies; its ID is generated and never reused, and Groups holds group IDs.
type Entity struct {
	ID       string
	Policies []string
	Groups   []string
}

// entitiesResource is the resource policies name the entity collection by; each entity is beneath it by ID.
const entitiesResource = "system/entities"

// EntityRepository stores entities by ID. Get returns ErrEntityNotFound for a missing ID and ErrUnreadableEntity
// for a corrupt record; Delete does not fail on a missing ID; every method returns ErrSealed while sealed.
type EntityRepository interface {
	Put(ctx context.Context, entity Entity) error
	Get(ctx context.Context, id string) (Entity, error)
	Delete(ctx context.Context, id string) error
}

// EntityService manages entities, validating each and authorizing its principal before the repository.
type EntityService struct {
	// Held by update and delete, so no delete lands between update's existence check and its write
	// and brings a deleted entity back with its tokens. Process-local: it assumes one instance.
	mu         sync.Mutex
	entities   EntityRepository
	random     Random
	authorizer authorization.Authorizer
}

// NewEntityService returns an EntityService over entities, taking IDs from random and asking authorizer before every operation.
func NewEntityService(entities EntityRepository, random Random, authorizer authorization.Authorizer) *EntityService {
	return &EntityService{entities: entities, random: random, authorizer: authorizer}
}

// CreateEntity stores entity under a newly generated ID if principal may create entities, replacing any ID it carries, and returns that ID.
func (s *EntityService) CreateEntity(ctx context.Context, principal authorization.Principal, entity Entity) (string, error) {
	if err := validateLists(entity); err != nil {
		return "", err
	}
	if err := s.authorizer.Authorize(ctx, principal, entitiesResource, authorization.CapabilityCreate); err != nil {
		return "", fmt.Errorf("identity: %w", err)
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

// GetEntity returns the entity with id if principal may read it; ErrEntityNotFound if there is none, ErrUnreadableEntity if its record is invalid.
func (s *EntityService) GetEntity(ctx context.Context, principal authorization.Principal, id string) (Entity, error) {
	if !validID(id) {
		return Entity{}, ErrInvalidEntityID
	}
	if err := s.authorizer.Authorize(ctx, principal, entitiesResource+"/"+id, authorization.CapabilityRead); err != nil {
		return Entity{}, fmt.Errorf("identity: %w", err)
	}

	return s.getEntity(ctx, id)
}

// getEntity reads without authorizing, for reads on the service's own behalf, such as resolving a token before any principal exists.
func (s *EntityService) getEntity(ctx context.Context, id string) (Entity, error) {
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

// DeleteEntity removes the entity with id if principal may delete it; a missing ID is not an error.
func (s *EntityService) DeleteEntity(ctx context.Context, principal authorization.Principal, id string) error {
	if !validID(id) {
		return ErrInvalidEntityID
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.authorizer.Authorize(ctx, principal, entitiesResource+"/"+id, authorization.CapabilityDelete); err != nil {
		return fmt.Errorf("identity: %w", err)
	}

	err := s.entities.Delete(ctx, id)
	if err != nil && !ours(err) {
		return fmt.Errorf("identity: %w", err)
	}
	return err
}

// UpdateEntity replaces an existing entity's policies and groups if principal may update it; it never creates one, so a missing ID is ErrEntityNotFound.
func (s *EntityService) UpdateEntity(ctx context.Context, principal authorization.Principal, entity Entity) error {
	if !validID(entity.ID) {
		return ErrInvalidEntityID
	}
	if err := validateLists(entity); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.authorizer.Authorize(ctx, principal, entitiesResource+"/"+entity.ID, authorization.CapabilityUpdate); err != nil {
		return fmt.Errorf("identity: %w", err)
	}

	// getEntity, not the repository: an entity that fails validation on read is not updated either.
	if _, err := s.getEntity(ctx, entity.ID); err != nil {
		return err
	}

	err := s.entities.Put(ctx, entity)
	if err != nil && !ours(err) {
		return fmt.Errorf("identity: %w", err)
	}
	return err
}
