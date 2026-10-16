package identity

import (
	"context"
	"fmt"

	"github.com/dimitrijegasic/seal-gate/internal/authorization"
)

// StoredUser is what is kept against a username: the entity it logs in as, and its password's hash.
type StoredUser struct {
	EntityID     string
	PasswordHash string
}

// usersResource is the resource policies name the user collection by; each user is beneath it by name.
const usersResource = "system/users"

// UserRepository stores users by name. Delete does not fail on a missing name; every method returns ErrSealed while sealed.
type UserRepository interface {
	Put(ctx context.Context, name string, user StoredUser) error
	Delete(ctx context.Context, name string) error
}

// PasswordHasher hashes passwords into strings that carry their own parameters.
type PasswordHasher interface {
	Hash(password []byte) (string, error)
}

// UserService manages users, each a username mapped to an entity and a password hash.
type UserService struct {
	users      UserRepository
	hasher     PasswordHasher
	entities   *EntityService
	authorizer authorization.Authorizer
}

// NewUserService returns a UserService over users, hashing with hasher, checking entities through entities and asking authorizer first.
func NewUserService(users UserRepository, hasher PasswordHasher, entities *EntityService, authorizer authorization.Authorizer) *UserService {
	return &UserService{users: users, hasher: hasher, entities: entities, authorizer: authorizer}
}

// SetUser stores name as a user of the entity with entityID and password's hash, replacing any user of that name, if principal
// may update it; the entity must exist, so a missing one is ErrEntityNotFound.
func (s *UserService) SetUser(ctx context.Context, principal authorization.Principal, name, entityID string, password []byte) error {
	if !validUsername(name) {
		return ErrInvalidUsername
	}
	if !validID(entityID) {
		return ErrInvalidEntityID
	}
	if len(password) == 0 || len(password) > maxPasswordLength {
		return ErrInvalidPassword
	}
	if err := s.authorizer.Authorize(ctx, principal, usersResource+"/"+name, authorization.CapabilityUpdate); err != nil {
		return fmt.Errorf("identity: %w", err)
	}

	if _, err := s.entities.getEntity(ctx, entityID); err != nil {
		return err
	}

	hash, err := s.hasher.Hash(password)
	if err != nil {
		return fmt.Errorf("identity: %w", err)
	}

	err = s.users.Put(ctx, name, StoredUser{EntityID: entityID, PasswordHash: hash})
	if err != nil && !ours(err) {
		return fmt.Errorf("identity: %w", err)
	}
	return err
}

// DeleteUser removes the user name if principal may delete it; a missing user is not an error.
func (s *UserService) DeleteUser(ctx context.Context, principal authorization.Principal, name string) error {
	if !validUsername(name) {
		return ErrInvalidUsername
	}
	if err := s.authorizer.Authorize(ctx, principal, usersResource+"/"+name, authorization.CapabilityDelete); err != nil {
		return fmt.Errorf("identity: %w", err)
	}

	err := s.users.Delete(ctx, name)
	if err != nil && !ours(err) {
		return fmt.Errorf("identity: %w", err)
	}
	return err
}
