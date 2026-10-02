package repository

import "github.com/dimitrijegasic/seal-gate/internal/barrier"

type Set struct {
	System *systemRepository
}

func NewSet(b *barrier.AEADBarrier) *Set {
	return &Set{
		System: &systemRepository{barrier: b},
	}
}
