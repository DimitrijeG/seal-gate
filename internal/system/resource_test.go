package system_test

import (
	"context"
	"errors"
	"testing"

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
