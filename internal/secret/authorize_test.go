package secret_test

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dimitrijegasic/seal-gate/internal/authorization"
	"github.com/dimitrijegasic/seal-gate/internal/secret"
)

func TestAuthorization(t *testing.T) {
	t.Run("a denied read never reaches the repository", func(t *testing.T) {
		s, repo, authorizer := newAuthorizedService(t)
		repo.secrets["db/password"] = []byte("secret")
		authorizer.err = authorization.ErrDenied

		_, err := s.Get(t.Context(), principal, "db/password")

		if !errors.Is(err, authorization.ErrDenied) {
			t.Errorf("err: got %v, want %v", err, authorization.ErrDenied)
		}
		if repo.calls != 0 {
			t.Errorf("calls: got %d, want 0", repo.calls)
		}
	})

	t.Run("each operation asks its capability on the path's resource", func(t *testing.T) {
		tests := []struct {
			name           string
			call           func(ctx context.Context, s *secret.Service) error
			wantResource   string
			wantCapability authorization.Capability
		}{
			{"get", func(ctx context.Context, s *secret.Service) error {
				_, err := s.Get(ctx, principal, "db/password")
				return err
			}, "secrets/db/password", authorization.CapabilityRead},
			{"delete", func(ctx context.Context, s *secret.Service) error {
				return s.Delete(ctx, principal, "db/password")
			}, "secrets/db/password", authorization.CapabilityDelete},
			{"list", func(ctx context.Context, s *secret.Service) error {
				_, err := s.List(ctx, principal, "db/")
				return err
			}, "secrets/db/", authorization.CapabilityList},
			{"list everything", func(ctx context.Context, s *secret.Service) error {
				_, err := s.List(ctx, principal, "")
				return err
			}, "secrets/", authorization.CapabilityList},
			{"put on a missing path", func(ctx context.Context, s *secret.Service) error {
				return s.Put(ctx, principal, "db/password", []byte("secret"))
			}, "secrets/db/password", authorization.CapabilityCreate},
			{"put on an existing path", func(ctx context.Context, s *secret.Service) error {
				return s.Put(ctx, principal, "existing", []byte("secret"))
			}, "secrets/existing", authorization.CapabilityUpdate},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				s, repo, authorizer := newAuthorizedService(t)
				repo.secrets["existing"] = []byte("old")

				_ = tt.call(t.Context(), s)

				if authorizer.resource != tt.wantResource {
					t.Errorf("resource: got %q, want %q", authorizer.resource, tt.wantResource)
				}
				if authorizer.capability != tt.wantCapability {
					t.Errorf("capability: got %q, want %q", authorizer.capability, tt.wantCapability)
				}
			})
		}
	})

	t.Run("the principal reaches the authorizer", func(t *testing.T) {
		for _, op := range operations {
			t.Run(op.name, func(t *testing.T) {
				s, _, authorizer := newAuthorizedService(t)

				_ = op.call(t.Context(), s)

				if !reflect.DeepEqual(authorizer.principal, principal) {
					t.Errorf("got %+v, want %+v", authorizer.principal, principal)
				}
			})
		}
	})

	t.Run("a denied operation never reaches the repository", func(t *testing.T) {
		tests := []struct {
			name string
			call func(ctx context.Context, s *secret.Service) error
		}{
			{"delete", func(ctx context.Context, s *secret.Service) error {
				return s.Delete(ctx, principal, "db/password")
			}},
			{"list", func(ctx context.Context, s *secret.Service) error {
				_, err := s.List(ctx, principal, "db/")
				return err
			}},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				s, repo, authorizer := newAuthorizedService(t)
				authorizer.err = authorization.ErrDenied

				err := tt.call(t.Context(), s)

				if !errors.Is(err, authorization.ErrDenied) {
					t.Errorf("err: got %v, want %v", err, authorization.ErrDenied)
				}
				if repo.calls != 0 {
					t.Errorf("calls: got %d, want 0", repo.calls)
				}
			})
		}
	})

	t.Run("a denied write stores nothing", func(t *testing.T) {
		s, repo, authorizer := newAuthorizedService(t)
		authorizer.err = authorization.ErrDenied

		err := s.Put(t.Context(), principal, "db/password", []byte("secret"))
		if !errors.Is(err, authorization.ErrDenied) {
			t.Fatalf("Put: got %v, want %v", err, authorization.ErrDenied)
		}

		if _, ok := repo.secrets["db/password"]; ok {
			t.Errorf("got a stored secret, want none")
		}
	})

	t.Run("a failed existence read is not taken as missing", func(t *testing.T) {
		s, repo, authorizer := newAuthorizedService(t)
		repoErr := errors.New("disk failed")
		repo.err = repoErr

		err := s.Put(t.Context(), principal, "db/password", []byte("secret"))

		if !errors.Is(err, repoErr) {
			t.Errorf("err: got %v, want %v", err, repoErr)
		}
		if authorizer.calls != 0 {
			t.Errorf("calls: got %d, want 0", authorizer.calls)
		}
	})

	t.Run("a create racing another on the same path is asked update", func(t *testing.T) {
		s := secret.New(newRacingRepository(), createOnlyAuthorizer{})
		ctx := t.Context()

		var errs [2]error
		var wg sync.WaitGroup
		for i := range errs {
			wg.Go(func() { errs[i] = s.Put(ctx, principal, "db/password", []byte{byte(i)}) })
		}
		wg.Wait()

		var denied int
		for _, err := range errs {
			switch {
			case errors.Is(err, authorization.ErrDenied):
				denied++
			case err != nil:
				t.Errorf("Put: got %v, want nil or %v", err, authorization.ErrDenied)
			}
		}
		if denied != 1 {
			t.Errorf("got %d denied, want 1", denied)
		}
	})
}

// createOnlyAuthorizer allows create and denies the rest, as a policy granting only create would.
type createOnlyAuthorizer struct{}

func (createOnlyAuthorizer) Authorize(_ context.Context, _ authorization.Principal, _ string, capability authorization.Capability) error {
	if capability == authorization.CapabilityCreate {
		return nil
	}
	return authorization.ErrDenied
}

// racingRepository holds the first Get, after it has read, until a second Get
// or 100 ms pass, so two unguarded writes both see the path missing.
type racingRepository struct {
	fakeRepository
	mu      sync.Mutex
	gets    atomic.Int32
	arrived chan struct{}
}

func newRacingRepository() *racingRepository {
	return &racingRepository{
		fakeRepository: fakeRepository{secrets: make(map[string][]byte)},
		arrived:        make(chan struct{}),
	}
}

func (r *racingRepository) Put(ctx context.Context, path string, value []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.fakeRepository.Put(ctx, path, value)
}

func (r *racingRepository) Get(ctx context.Context, path string) ([]byte, error) {
	r.mu.Lock()
	value, err := r.fakeRepository.Get(ctx, path)
	r.mu.Unlock()

	switch r.gets.Add(1) {
	case 1:
		select {
		case <-r.arrived:
		case <-time.After(100 * time.Millisecond):
		}
	case 2:
		close(r.arrived)
	}
	return value, err
}
