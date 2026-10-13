// Package repository implements every domain repository once: the system record
// directly on storage, so it loads while sealed, and the rest through the barrier.
package repository

import (
	"github.com/dimitrijegasic/seal-gate/internal/barrier"
	"github.com/dimitrijegasic/seal-gate/internal/storage"
)

// Set holds one implementation of every domain repository over one backend.
type Set struct {
	System *systemRepository
	Secret *secretRepository
	Policy *policyRepository
	Entity *entityRepository
	Token  *tokenRepository
	Group  *groupRepository
}

// NewSet builds every repository over backend, the encrypted ones through encrypted.
func NewSet(backend storage.Backend, encrypted *barrier.AEADBarrier) *Set {
	return &Set{
		System: &systemRepository{backend: backend},
		Secret: &secretRepository{encrypted: encrypted},
		Policy: &policyRepository{encrypted: encrypted},
		Entity: &entityRepository{encrypted: encrypted},
		Token:  &tokenRepository{encrypted: encrypted},
		Group:  &groupRepository{encrypted: encrypted},
	}
}
