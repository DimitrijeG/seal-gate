package identity

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"

	"github.com/dimitrijegasic/seal-gate/internal/authorization"
)

// Group assigns its policies to the entities that name it; its ID is generated and never reused, and it holds no member list.
// Alias is an optional name for it, unique across groups; empty means none.
type Group struct {
	ID       string
	Alias    string
	Policies []string
}

// GroupSummary is what a listing shows of a group: never its policies, which only a read of the group reveals.
type GroupSummary struct {
	ID    string
	Alias string
}

// groupsResource is the resource policies name the group collection by; each group is beneath it by ID.
const groupsResource = "system/groups"

// GroupRepository stores groups by ID. Get returns ErrGroupNotFound for a missing ID and ErrUnreadableGroup
// for a corrupt record; Delete does not fail on a missing ID; List returns every ID in byte order;
// every method returns ErrSealed while sealed.
type GroupRepository interface {
	Put(ctx context.Context, group Group) error
	Get(ctx context.Context, id string) (Group, error)
	Delete(ctx context.Context, id string) error
	List(ctx context.Context) ([]string, error)
}

// GroupService manages groups, authorizing each operation's principal before the repository, and combines an entity's policies with its groups'.
type GroupService struct {
	// Held by create, update and delete, so no delete lands between update's existence check and its write and re-grants
	// a deleted group's policies, and no two writes both find an alias free. Process-local: it assumes one instance.
	mu         sync.Mutex
	groups     GroupRepository
	random     Random
	authorizer authorization.Authorizer
}

// NewGroupService returns a GroupService over groups, taking IDs from random and asking authorizer before every operation.
func NewGroupService(groups GroupRepository, random Random, authorizer authorization.Authorizer) *GroupService {
	return &GroupService{groups: groups, random: random, authorizer: authorizer}
}

// CreateGroup stores group under a newly generated ID if principal may create groups, replacing any ID it carries,
// and returns that ID; an alias another group holds is ErrGroupAliasTaken.
func (s *GroupService) CreateGroup(ctx context.Context, principal authorization.Principal, group Group) (string, error) {
	if err := validateGroup(group); err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.authorizer.Authorize(ctx, principal, groupsResource, authorization.CapabilityCreate); err != nil {
		return "", fmt.Errorf("identity: %w", err)
	}

	if err := s.checkAlias(ctx, "", group.Alias); err != nil {
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

// GetGroup returns the group with id if principal may read it; ErrGroupNotFound if there is none, ErrUnreadableGroup if its record is invalid.
func (s *GroupService) GetGroup(ctx context.Context, principal authorization.Principal, id string) (Group, error) {
	if !validID(id) {
		return Group{}, ErrInvalidGroupID
	}
	if err := s.authorizer.Authorize(ctx, principal, groupsResource+"/"+id, authorization.CapabilityRead); err != nil {
		return Group{}, fmt.Errorf("identity: %w", err)
	}

	return s.getGroup(ctx, id)
}

// getGroup reads without authorizing, for reads on the service's own behalf, such as resolving a token's groups before any principal exists.
func (s *GroupService) getGroup(ctx context.Context, id string) (Group, error) {
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

// getListed reads an ID the repository listed, so one that is not an ID is a corrupt store, not the caller's mistake.
func (s *GroupService) getListed(ctx context.Context, id string) (Group, error) {
	group, err := s.getGroup(ctx, id)
	if errors.Is(err, ErrInvalidGroupID) {
		return Group{}, ErrUnreadableGroup
	}
	return group, err
}

// ListGroups returns every group's summary in ID byte order if principal may list the group collection. One unreadable
// group fails the listing; one deleted while listed is left out.
func (s *GroupService) ListGroups(ctx context.Context, principal authorization.Principal) ([]GroupSummary, error) {
	if err := s.authorizer.Authorize(ctx, principal, groupsResource, authorization.CapabilityList); err != nil {
		return nil, fmt.Errorf("identity: %w", err)
	}

	ids, err := s.groups.List(ctx)
	if err != nil && !ours(err) {
		return nil, fmt.Errorf("identity: %w", err)
	}
	if err != nil {
		return nil, err
	}

	summaries := make([]GroupSummary, 0, len(ids))
	for _, id := range ids {
		group, err := s.getListed(ctx, id)
		// Deleted since the List: leaving it out is the right answer, and the listing takes no lock to prevent it.
		if errors.Is(err, ErrGroupNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		summaries = append(summaries, GroupSummary{ID: group.ID, Alias: group.Alias})
	}
	return summaries, nil
}

// DeleteGroup removes the group with id if principal may delete it; a missing ID is not an error.
func (s *GroupService) DeleteGroup(ctx context.Context, principal authorization.Principal, id string) error {
	if !validID(id) {
		return ErrInvalidGroupID
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.authorizer.Authorize(ctx, principal, groupsResource+"/"+id, authorization.CapabilityDelete); err != nil {
		return fmt.Errorf("identity: %w", err)
	}

	err := s.groups.Delete(ctx, id)
	if err != nil && !ours(err) {
		return fmt.Errorf("identity: %w", err)
	}
	return err
}

// UpdateGroup replaces an existing group's alias and policies if principal may update it; it never creates one,
// so a missing ID is ErrGroupNotFound, and an alias another group holds is ErrGroupAliasTaken.
func (s *GroupService) UpdateGroup(ctx context.Context, principal authorization.Principal, group Group) error {
	if !validID(group.ID) {
		return ErrInvalidGroupID
	}
	if err := validateGroup(group); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.authorizer.Authorize(ctx, principal, groupsResource+"/"+group.ID, authorization.CapabilityUpdate); err != nil {
		return fmt.Errorf("identity: %w", err)
	}

	// getGroup, not the repository: a group that fails validation on read is not updated either.
	if _, err := s.getGroup(ctx, group.ID); err != nil {
		return err
	}
	if err := s.checkAlias(ctx, group.ID, group.Alias); err != nil {
		return err
	}

	err := s.groups.Put(ctx, group)
	if err != nil && !ours(err) {
		return fmt.Errorf("identity: %w", err)
	}
	return err
}

// checkAlias returns ErrGroupAliasTaken if a group other than id holds alias; the caller holds mu. Every group is read,
// so an unreadable one fails the check rather than hide a duplicate.
func (s *GroupService) checkAlias(ctx context.Context, id, alias string) error {
	if alias == "" {
		return nil
	}

	ids, err := s.groups.List(ctx)
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
		group, err := s.getListed(ctx, other)
		if err != nil {
			return err
		}
		if group.Alias == alias {
			return ErrGroupAliasTaken
		}
	}
	return nil
}

// EffectivePolicies returns the entity's own policy names, then each of its groups', each name once.
// A missing group is skipped; any other read failure, an unreadable group included, is returned.
func (s *GroupService) EffectivePolicies(ctx context.Context, entity Entity) ([]string, error) {
	seen := make(map[string]bool)
	policies := make([]string, 0, len(entity.Policies))
	add := func(names []string) {
		for _, name := range names {
			if !seen[name] {
				seen[name] = true
				policies = append(policies, name)
			}
		}
	}

	add(entity.Policies)
	for _, groupID := range entity.Groups {
		group, err := s.getGroup(ctx, groupID)
		// Before the error return: a deleted group grants nothing, but any other failure could hide a deny.
		if errors.Is(err, ErrGroupNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		add(group.Policies)
	}

	return policies, nil
}
