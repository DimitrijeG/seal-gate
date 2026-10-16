package identity

import (
	"context"
	"errors"
	"fmt"
	"time"

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
	Get(ctx context.Context, name string) (StoredUser, error)
	Delete(ctx context.Context, name string) error
}

// PasswordHasher hashes passwords into strings that carry their own parameters.
type PasswordHasher interface {
	Hash(password []byte) (string, error)
	Verify(password []byte, encoded string) (bool, error)
}

// UserService manages users, each a username mapped to an entity and a password hash.
type UserService struct {
	users      UserRepository
	hasher     PasswordHasher
	entities   *EntityService
	tokens     *TokenService
	authorizer authorization.Authorizer
	// An unknown user's login verifies against this, so it costs what a known user's does.
	dummyHash string
}

var dummyPassword = []byte("seal-gate dummy password")

// NewUserService returns a UserService over users, hashing with hasher, checking entities through entities, issuing login
// tokens through tokens and asking authorizer first. It hashes a dummy password for logins of unknown users, so a failed hash fails it.
func NewUserService(users UserRepository, hasher PasswordHasher, entities *EntityService, tokens *TokenService, authorizer authorization.Authorizer) (*UserService, error) {
	dummyHash, err := hasher.Hash(dummyPassword)
	if err != nil {
		return nil, fmt.Errorf("identity: %w", err)
	}
	return &UserService{users: users, hasher: hasher, entities: entities, tokens: tokens, authorizer: authorizer, dummyHash: dummyHash}, nil
}

// Login issues a token for name's entity if password matches, returning it and its expiry; every refusal is
// ErrInvalidCredentials. Only its hash is stored, so the caller must clear the token once delivered.
func (s *UserService) Login(ctx context.Context, name string, password []byte) ([]byte, time.Time, error) {
	// Refused without a Verify: validity is a public rule, so its timing tells the caller nothing.
	if !validUsername(name) || !validPassword(password) {
		return nil, time.Time{}, ErrInvalidCredentials
	}

	user, err := s.users.Get(ctx, name)
	found := err == nil
	switch {
	case errors.Is(err, ErrUserNotFound):
		user = StoredUser{PasswordHash: s.dummyHash}
	case err != nil && !ours(err):
		return nil, time.Time{}, fmt.Errorf("identity: %w", err)
	case err != nil:
		return nil, time.Time{}, err
	// Checked here, not by getEntity: a bad stored ID is a corrupt record, not the caller's mistake.
	case !validID(user.EntityID) || user.PasswordHash == "":
		return nil, time.Time{}, ErrUnreadableUser
	}

	ok, err := s.hasher.Verify(password, user.PasswordHash)
	if err != nil {
		// Replaced, not wrapped: a hash that will not parse is a corrupt record, whatever the hasher calls it.
		return nil, time.Time{}, ErrUnreadableUser
	}
	if !ok || !found {
		return nil, time.Time{}, ErrInvalidCredentials
	}

	_, err = s.entities.getEntity(ctx, user.EntityID)
	if errors.Is(err, ErrEntityNotFound) {
		return nil, time.Time{}, ErrInvalidCredentials
	}
	if err != nil {
		return nil, time.Time{}, err
	}
	return s.tokens.issue(ctx, user.EntityID, 0)
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
	if !validPassword(password) {
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
