package identity

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"

	"github.com/dimitrijegasic/seal-gate/internal/authorization"
)

// Entity is an identity with its own policies; its ID is generated and never reused, and Groups holds group IDs.
// Alias is an optional name for it, unique across entities; empty means none.
type Entity struct {
	ID       string
	Alias    string
	Policies []string
	Groups   []string
}

// EntitySummary is what a listing shows of an entity: never its policies or groups, which only a read of the entity reveals.
type EntitySummary struct {
	ID    string
	Alias string
}

// entitiesResource is the resource policies name the entity collection by; each entity is beneath it by ID.
const entitiesResource = "system/entities"

// EntityRepository stores entities by ID. Get returns ErrEntityNotFound for a missing ID and ErrUnreadableEntity
// for a corrupt record; Delete does not fail on a missing ID; List returns every ID in byte order;
// every method returns ErrSealed while sealed.
type EntityRepository interface {
	Put(ctx context.Context, entity Entity) error
	Get(ctx context.Context, id string) (Entity, error)
	Delete(ctx context.Context, id string) error
	List(ctx context.Context) ([]string, error)
}

// EntityService manages entities, validating each and authorizing its principal before the repository.
type EntityService struct {
	// Held by create, update and delete, so no delete lands between update's existence check and its write and brings
	// a deleted entity back with its tokens, and no two writes both find an alias free. Process-local: it assumes one instance.
	mu         sync.Mutex
	entities   EntityRepository
	random     Random
	authorizer authorization.Authorizer
}

// NewEntityService returns an EntityService over entities, taking IDs from random and asking authorizer before every operation.
func NewEntityService(entities EntityRepository, random Random, authorizer authorization.Authorizer) *EntityService {
	return &EntityService{entities: entities, random: random, authorizer: authorizer}
}

// CreateEntity stores entity under a newly generated ID if principal may create entities, replacing any ID it carries,
// and returns that ID; an alias another entity holds is ErrAliasTaken.
func (s *EntityService) CreateEntity(ctx context.Context, principal authorization.Principal, entity Entity) (string, error) {
	if err := validateLists(entity); err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.authorizer.Authorize(ctx, principal, entitiesResource, authorization.CapabilityCreate); err != nil {
		return "", fmt.Errorf("identity: %w", err)
	}

	if err := s.checkAlias(ctx, "", entity.Alias); err != nil {
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

// getListed reads an ID the repository listed, so one that is not an ID is a corrupt store, not the caller's mistake.
func (s *EntityService) getListed(ctx context.Context, id string) (Entity, error) {
	entity, err := s.getEntity(ctx, id)
	if errors.Is(err, ErrInvalidEntityID) {
		return Entity{}, ErrUnreadableEntity
	}
	return entity, err
}

// ListEntities returns every entity's summary in ID byte order if principal may list the entity collection. One unreadable
// entity fails the listing; one deleted while listed is left out.
func (s *EntityService) ListEntities(ctx context.Context, principal authorization.Principal) ([]EntitySummary, error) {
	if err := s.authorizer.Authorize(ctx, principal, entitiesResource, authorization.CapabilityList); err != nil {
		return nil, fmt.Errorf("identity: %w", err)
	}

	ids, err := s.entities.List(ctx)
	if err != nil && !ours(err) {
		return nil, fmt.Errorf("identity: %w", err)
	}
	if err != nil {
		return nil, err
	}

	summaries := make([]EntitySummary, 0, len(ids))
	for _, id := range ids {
		entity, err := s.getListed(ctx, id)
		// Deleted since the List: leaving it out is the right answer, and the listing takes no lock to prevent it.
		if errors.Is(err, ErrEntityNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		summaries = append(summaries, EntitySummary{ID: entity.ID, Alias: entity.Alias})
	}
	return summaries, nil
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

// UpdateEntity replaces an existing entity's alias, policies and groups if principal may update it; it never creates one,
// so a missing ID is ErrEntityNotFound, and an alias another entity holds is ErrAliasTaken.
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
	if err := s.checkAlias(ctx, entity.ID, entity.Alias); err != nil {
		return err
	}

	err := s.entities.Put(ctx, entity)
	if err != nil && !ours(err) {
		return fmt.Errorf("identity: %w", err)
	}
	return err
}

// checkAlias returns ErrAliasTaken if an entity other than id holds alias; the caller holds mu. Every entity is read,
// so an unreadable one fails the check rather than hide a duplicate.
func (s *EntityService) checkAlias(ctx context.Context, id, alias string) error {
	if alias == "" {
		return nil
	}

	ids, err := s.entities.List(ctx)
	if err != nil && !ours(err) {
		return fmt.Errorf("identity: %w", err)
	}
	if err != nil {
		return err
	}

	for _, other := range ids {
		if other == id {
			continue
		}
		entity, err := s.getListed(ctx, other)
		if err != nil {
			return err
		}
		if entity.Alias == alias {
			return ErrAliasTaken
		}
	}
	return nil
}
