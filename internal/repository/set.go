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
}

func NewSet(backend storage.Backend, encrypted *barrier.AEADBarrier) *Set {
	return &Set{
		System: &systemRepository{backend: backend},
		Secret: &secretRepository{encrypted: encrypted},
	}
}
