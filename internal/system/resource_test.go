package system_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/dimitrijegasic/seal-gate/internal/authorization"
	"github.com/dimitrijegasic/seal-gate/internal/system"
)

var errActivate = errors.New("activate failed")

// fakeResource counts its calls and whether the key was installed at each. No lock: Service calls it under its own.
type fakeResource struct {
	active                system.ActiveKeyController
	activations           int
	deactivations         int
	installedAtActivate   bool
	installedAtDeactivate bool
	activateErr           error
}

func (r *fakeResource) Activate(context.Context) error {
	r.activations++
	r.installedAtActivate = r.active.IsInstalled()
	return r.activateErr
}

func (r *fakeResource) Deactivate() {
	r.deactivations++
	r.installedAtDeactivate = r.active.IsInstalled()
}

// blockingResource holds each Activate and Deactivate once its channels are set: it reports on entered and waits for
// release. Nil channels pass straight through, so a test can unseal before it starts holding.
type blockingResource struct {
	entered chan struct{}
	release chan struct{}
	freed   sync.Once
}

func (r *blockingResource) Activate(context.Context) error {
	r.hold()
	return nil
}

func (r *blockingResource) Deactivate() { r.hold() }

func (r *blockingResource) hold() {
	if r.entered == nil {
		return
	}
	r.entered <- struct{}{}
	<-r.release
}

// block makes every later call hold, until the test ends.
func (r *blockingResource) block(t *testing.T) {
	t.Helper()
	r.entered = make(chan struct{}, 1)
	r.release = make(chan struct{})
	t.Cleanup(func() { r.freed.Do(func() { close(r.release) }) })
}

// newBlockingService returns an initialized, sealed service over a blockingResource not yet holding, and its result.
func newBlockingService(t *testing.T) (*system.Service, *blockingResource, system.InitResult) {
	t.Helper()
	resource := &blockingResource{}
	s, _ := newServiceOver(t, &fakeRepository{}, &fakeAuthorizer{}, resource, &fakeTimer{})
	return s, resource, initialize(t, s)
}

// isRootWithin fails rather than hangs when IsRoot waits on a lifecycle change.
func isRootWithin(t *testing.T, s *system.Service, token []byte) bool {
	t.Helper()
	answer := make(chan bool, 1)
	go func() { answer <- s.IsRoot(token) }()
	select {
	case root := <-answer:
		return root
	case <-time.After(time.Second):
		t.Fatalf("IsRoot: got no answer within a second")
	}
	return false
}

// unsealHeld submits the threshold share in the background and returns once activation holds.
func unsealHeld(t *testing.T, s *system.Service, resource *blockingResource, shares [][]byte) {
	t.Helper()
	last := sealConfig.Threshold - 1
	unsealWith(t, s, shares[:last])
	resource.block(t)
	go func() { _, _ = s.Unseal(context.Background(), shares[last]) }()
	<-resource.entered
}

// sealHeld unseals, then seals in the background and returns once deactivation holds.
func sealHeld(t *testing.T, s *system.Service, resource *blockingResource, shares [][]byte) {
	t.Helper()
	unsealWith(t, s, shares[:sealConfig.Threshold])
	resource.block(t)
	go func() { _ = s.Seal(context.Background(), principal) }()
	<-resource.entered
}

// newResourceService returns an initialized, sealed service over resource, and the shares to unseal it.
func newResourceService(t *testing.T, resource *fakeResource) (*system.Service, system.InitResult) {
	t.Helper()
	s, _ := newServiceWith(t, &fakeRepository{}, &fakeAuthorizer{}, resource)
	return s, initialize(t, s)
}

// unsealReturning submits shares that are all expected to be accepted but the last, and returns the last one's error.
func unsealReturning(t *testing.T, s *system.Service, shares [][]byte) error {
	t.Helper()
	last := len(shares) - 1
	unsealWith(t, s, shares[:last])
	_, err := s.Unseal(t.Context(), shares[last])
	return err
}

func TestUnsealedResource(t *testing.T) {
	t.Run("unsealing activates the resource once", func(t *testing.T) {
		resource := &fakeResource{}
		s, result := newResourceService(t, resource)

		unsealWith(t, s, result.Shares[:sealConfig.Threshold])

		if resource.activations != 1 {
			t.Errorf("got %d activations, want 1", resource.activations)
		}
	})

	t.Run("unsealing activates after the key is installed", func(t *testing.T) {
		resource := &fakeResource{}
		s, result := newResourceService(t, resource)

		unsealWith(t, s, result.Shares[:sealConfig.Threshold])

		if !resource.installedAtActivate {
			t.Error("key not installed at activation")
		}
	})

	t.Run("a failed activation fails the unseal", func(t *testing.T) {
		resource := &fakeResource{activateErr: errActivate}
		s, result := newResourceService(t, resource)

		err := unsealReturning(t, s, result.Shares[:sealConfig.Threshold])

		if !errors.Is(err, errActivate) {
			t.Errorf("got %v, want %v", err, errActivate)
		}
	})

	t.Run("a failed activation leaves the key cleared", func(t *testing.T) {
		resource := &fakeResource{activateErr: errActivate}
		s, keys := newServiceWith(t, &fakeRepository{}, &fakeAuthorizer{}, resource)

		_ = unsealReturning(t, s, initialize(t, s).Shares[:sealConfig.Threshold])

		if keys.IsInstalled() {
			t.Error("key still installed")
		}
	})

	t.Run("a failed activation leaves the root token not root", func(t *testing.T) {
		resource := &fakeResource{activateErr: errActivate}
		s, result := newResourceService(t, resource)

		_ = unsealReturning(t, s, result.Shares[:sealConfig.Threshold])

		if s.IsRoot(result.RootToken) {
			t.Error("root token is root")
		}
	})

	t.Run("the root check answers while an unseal is activating", func(t *testing.T) {
		s, resource, result := newBlockingService(t)
		unsealHeld(t, s, resource, result.Shares)

		isRootWithin(t, s, result.RootToken)
	})

	t.Run("no token is root while an unseal is activating", func(t *testing.T) {
		s, resource, result := newBlockingService(t)
		unsealHeld(t, s, resource, result.Shares)

		if isRootWithin(t, s, result.RootToken) {
			t.Error("root token is root")
		}
	})

	t.Run("the root check answers while a seal is deactivating", func(t *testing.T) {
		s, resource, result := newBlockingService(t)
		sealHeld(t, s, resource, result.Shares)

		isRootWithin(t, s, result.RootToken)
	})

	t.Run("no token is root while a seal is deactivating", func(t *testing.T) {
		s, resource, result := newBlockingService(t)
		sealHeld(t, s, resource, result.Shares)

		if isRootWithin(t, s, result.RootToken) {
			t.Error("root token is root")
		}
	})

	t.Run("sealing deactivates the resource", func(t *testing.T) {
		resource := &fakeResource{}
		s, result := newResourceService(t, resource)
		unsealWith(t, s, result.Shares[:sealConfig.Threshold])

		if err := s.Seal(t.Context(), principal); err != nil {
			t.Fatalf("Seal: %v", err)
		}

		if resource.deactivations != 1 {
			t.Errorf("got %d deactivations, want 1", resource.deactivations)
		}
	})

	t.Run("sealing deactivates before the key is cleared", func(t *testing.T) {
		resource := &fakeResource{}
		s, result := newResourceService(t, resource)
		unsealWith(t, s, result.Shares[:sealConfig.Threshold])

		if err := s.Seal(t.Context(), principal); err != nil {
			t.Fatalf("Seal: %v", err)
		}

		if !resource.installedAtDeactivate {
			t.Error("key cleared before deactivation")
		}
	})

	t.Run("sealing a sealed instance does not deactivate", func(t *testing.T) {
		resource := &fakeResource{}
		s, _ := newResourceService(t, resource)

		if err := s.Seal(t.Context(), principal); err != nil {
			t.Fatalf("Seal: %v", err)
		}

		if resource.deactivations != 0 {
			t.Errorf("got %d deactivations, want 0", resource.deactivations)
		}
	})

	t.Run("a denied seal does not deactivate", func(t *testing.T) {
		resource := &fakeResource{}
		s, _ := newServiceWith(t, &fakeRepository{}, &fakeAuthorizer{err: authorization.ErrDenied}, resource)
		unsealWith(t, s, initialize(t, s).Shares[:sealConfig.Threshold])

		_ = s.Seal(t.Context(), principal)

		if resource.deactivations != 0 {
			t.Errorf("got %d deactivations, want 0", resource.deactivations)
		}
	})
}
