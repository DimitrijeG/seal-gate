package repository

import (
	"context"
	"errors"

	"github.com/dimitrijegasic/seal-gate/internal/barrier"
	"github.com/dimitrijegasic/seal-gate/internal/identity"
)

var errNotImplemented = errors.New("repository: not implemented")

type groupRepository struct {
	encrypted *barrier.AEADBarrier
}

var _ identity.GroupRepository = (*groupRepository)(nil)

// TODO: encode and store the group through the barrier.
func (r *groupRepository) Put(ctx context.Context, group identity.Group) error {
	return errNotImplemented
}

// TODO: read and decode the group, mapping sealed, not found and unreadable.
func (r *groupRepository) Get(ctx context.Context, id string) (identity.Group, error) {
	return identity.Group{}, errNotImplemented
}

// TODO: delete the group's key.
func (r *groupRepository) Delete(ctx context.Context, id string) error {
	return errNotImplemented
}
