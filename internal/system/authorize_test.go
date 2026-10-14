package system_test

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"

	"github.com/dimitrijegasic/seal-gate/internal/authorization"
)

// fakeAuthorizer records the last decision asked for; it allows unless err is set.
// Locked: the race test seals from several goroutines at once.
type fakeAuthorizer struct {
	mu         sync.Mutex
	principal  authorization.Principal
	resource   string
	capability authorization.Capability
	calls      int
	err        error
}

func (a *fakeAuthorizer) Authorize(_ context.Context, principal authorization.Principal, resource string, capability authorization.Capability) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.calls++
	a.principal = principal
	a.resource = resource
	a.capability = capability
	return a.err
}

func TestAuthorization(t *testing.T) {
	t.Run("a denied seal keeps the key", func(t *testing.T) {
		s, keys := newUnsealedServiceWith(t, &fakeAuthorizer{err: authorization.ErrDenied})

		err := s.Seal(t.Context(), principal)

		if !errors.Is(err, authorization.ErrDenied) {
			t.Errorf("err: got %v, want %v", err, authorization.ErrDenied)
		}
		if !keys.IsInstalled() {
			t.Error("IsInstalled: got false, want true")
		}
	})

	t.Run("seal asks update on system/seal", func(t *testing.T) {
		authorizer := &fakeAuthorizer{}
		s, _ := newUnsealedServiceWith(t, authorizer)

		if err := s.Seal(t.Context(), principal); err != nil {
			t.Fatalf("Seal: %v", err)
		}

		if authorizer.resource != "system/seal" {
			t.Errorf("resource: got %q, want %q", authorizer.resource, "system/seal")
		}
		if authorizer.capability != authorization.CapabilityUpdate {
			t.Errorf("capability: got %q, want %q", authorizer.capability, authorization.CapabilityUpdate)
		}
	})

	t.Run("the principal reaches the authorizer", func(t *testing.T) {
		authorizer := &fakeAuthorizer{}
		s, _ := newUnsealedServiceWith(t, authorizer)

		if err := s.Seal(t.Context(), principal); err != nil {
			t.Fatalf("Seal: %v", err)
		}

		if !reflect.DeepEqual(authorizer.principal, principal) {
			t.Errorf("got %+v, want %+v", authorizer.principal, principal)
		}
	})
}
