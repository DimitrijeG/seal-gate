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

func (u StoredUser) readable() bool {
	return validID(u.EntityID) && u.PasswordHash != ""
}

// UserSummary is what a listing shows of a user: never its password hash.
type UserSummary struct {
	Name     string
	EntityID string
}

// usersResource is the resource policies name the user collection by; each user is beneath it by name.
const usersResource = "system/users"

// UserRepository stores users by name. Delete does not fail on a missing name; List returns every name in byte order;
// every method returns ErrSealed while sealed.
type UserRepository interface {
	Put(ctx context.Context, name string, user StoredUser) error
	Get(ctx context.Context, name string) (StoredUser, error)
	Delete(ctx context.Context, name string) error
	List(ctx context.Context) ([]string, error)
}

// PasswordHasher hashes passwords into strings that carry their own parameters.
type PasswordHasher interface {
	Hash(password []byte) (string, error)
	Verify(password []byte, encoded string) (bool, error)
	Check(encoded string) error
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
	// One per hash in progress: each holds megabytes, so concurrent logins must not multiply it without bound.
	hashSlots chan struct{}
}

var dummyPassword = []byte("seal-gate dummy password")

// NewUserService returns a UserService over users, hashing with hasher at most hashLimit at a time, checking entities through
// entities, issuing login tokens through tokens and asking authorizer first. A Login or SetUser past the limit waits, failing
// with its context's error if that ends first. The dummy hash for unknown users is made here, so a failed hash fails it, and a
// hashLimit below one is ErrInvalidHashLimit.
func NewUserService(users UserRepository, hasher PasswordHasher, entities *EntityService, tokens *TokenService, authorizer authorization.Authorizer, hashLimit int) (*UserService, error) {
	// No slots would block every login forever, with no error to say why.
	if hashLimit < 1 {
		return nil, ErrInvalidHashLimit
	}
	dummyHash, err := hasher.Hash(dummyPassword)
	if err != nil {
		return nil, fmt.Errorf("identity: %w", err)
	}
	return &UserService{users: users, hasher: hasher, entities: entities, tokens: tokens, authorizer: authorizer, dummyHash: dummyHash,
		hashSlots: make(chan struct{}, hashLimit)}, nil
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
	case !user.readable():
		return nil, time.Time{}, ErrUnreadableUser
	}

	select {
	case s.hashSlots <- struct{}{}:
	case <-ctx.Done():
		return nil, time.Time{}, fmt.Errorf("identity: %w", ctx.Err())
	}
	ok, err := s.hasher.Verify(password, user.PasswordHash)
	<-s.hashSlots
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

	select {
	case s.hashSlots <- struct{}{}:
	case <-ctx.Done():
		return fmt.Errorf("identity: %w", ctx.Err())
	}
	hash, err := s.hasher.Hash(password)
	<-s.hashSlots
	if err != nil {
		return fmt.Errorf("identity: %w", err)
	}

	err = s.users.Put(ctx, name, StoredUser{EntityID: entityID, PasswordHash: hash})
	if err != nil && !ours(err) {
		return fmt.Errorf("identity: %w", err)
	}
	return err
}

// ListUsers returns every user's summary in name byte order if principal may list the user collection. One unreadable
// user fails the listing; one deleted while listed is left out.
func (s *UserService) ListUsers(ctx context.Context, principal authorization.Principal) ([]UserSummary, error) {
	if err := s.authorizer.Authorize(ctx, principal, usersResource, authorization.CapabilityList); err != nil {
		return nil, fmt.Errorf("identity: %w", err)
	}

	names, err := s.users.List(ctx)
	if err != nil && !ours(err) {
		return nil, fmt.Errorf("identity: %w", err)
	}
	if err != nil {
		return nil, err
	}

	summaries := make([]UserSummary, 0, len(names))
	for _, name := range names {
		// A listed key that is not a username is a corrupt store, not the caller's mistake.
		if !validUsername(name) {
			return nil, ErrUnreadableUser
		}
		user, err := s.users.Get(ctx, name)
		// Deleted since the List: leaving it out is the right answer, and the listing takes no lock to prevent it.
		if errors.Is(err, ErrUserNotFound) {
			continue
		}
		if err != nil && !ours(err) {
			return nil, fmt.Errorf("identity: %w", err)
		}
		if err != nil {
			return nil, err
		}
		if !s.intact(user) {
			return nil, ErrUnreadableUser
		}
		summaries = append(summaries, UserSummary{Name: name, EntityID: user.EntityID})
	}
	return summaries, nil
}

// intact reports whether user is a record Login could use: a valid entity ID and a hash the hasher parses.
// Check, not Verify: a parse finds a hash Login would refuse without a derivation per user.
func (s *UserService) intact(user StoredUser) bool {
	return user.readable() && s.hasher.Check(user.PasswordHash) == nil
}

// GetUser returns the entity the user name logs in as if principal may read that user, never its hash; a missing user is ErrUserNotFound.
func (s *UserService) GetUser(ctx context.Context, principal authorization.Principal, name string) (UserSummary, error) {
	if !validUsername(name) {
		return UserSummary{}, ErrInvalidUsername
	}
	if err := s.authorizer.Authorize(ctx, principal, usersResource+"/"+name, authorization.CapabilityRead); err != nil {
		return UserSummary{}, fmt.Errorf("identity: %w", err)
	}

	user, err := s.users.Get(ctx, name)
	if err != nil && !ours(err) {
		return UserSummary{}, fmt.Errorf("identity: %w", err)
	}
	if err != nil {
		return UserSummary{}, err
	}
	if !s.intact(user) {
		return UserSummary{}, ErrUnreadableUser
	}
	return UserSummary{Name: name, EntityID: user.EntityID}, nil
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
