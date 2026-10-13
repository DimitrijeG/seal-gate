package identity

import (
	"context"
	"encoding/hex"
	"fmt"
	"sync"
)

// Group assigns its policies to the entities that name it; its ID is generated and never reused, and it holds no member list.
type Group struct {
	ID       string
	Policies []string
}

// GroupRepository stores groups by ID. Get returns ErrGroupNotFound for a missing ID and ErrUnreadableGroup
// for a corrupt record; Delete does not fail on a missing ID; every method returns ErrSealed while sealed.
type GroupRepository interface {
	Put(ctx context.Context, group Group) error
	Get(ctx context.Context, id string) (Group, error)
	Delete(ctx context.Context, id string) error
}

// GroupService manages groups, validating them before they reach the repository.
type GroupService struct {
	// Held by update and delete, so no delete lands between update's existence check and its write and
	// brings a deleted group back, re-granting its policies. Process-local: it assumes one instance.
	mu     sync.Mutex
	groups GroupRepository
	random Random
}

// NewGroupService returns a GroupService over groups, taking IDs from random.
func NewGroupService(groups GroupRepository, random Random) *GroupService {
	return &GroupService{groups: groups, random: random}
}

// CreateGroup stores group under a newly generated ID, replacing any ID it carries, and returns that ID.
func (s *GroupService) CreateGroup(ctx context.Context, group Group) (string, error) {
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
func (s *GroupService) GetGroup(ctx context.Context, id string) (Group, error) {
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
func (s *GroupService) DeleteGroup(ctx context.Context, id string) error {
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
func (s *GroupService) UpdateGroup(ctx context.Context, group Group) error {
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
