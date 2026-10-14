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
		repo.secrets["db/password"] = secret.Entry{Value: []byte("secret")}
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
			{"generate", func(ctx context.Context, s *secret.Service) error {
				_, err := s.Generate(ctx, principal, "db/password", 32)
				return err
			}, "secrets/db/password", authorization.CapabilityCreate},
			{"rotate", func(ctx context.Context, s *secret.Service) error {
				_, err := s.Rotate(ctx, principal, "db/password")
				return err
			}, "secrets/db/password", authorization.CapabilityRotate},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				s, repo, authorizer := newAuthorizedService(t)
				repo.secrets["existing"] = secret.Entry{Value: []byte("old")}

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
			{"generate", func(ctx context.Context, s *secret.Service) error {
				_, err := s.Generate(ctx, principal, "db/password", 32)
				return err
			}},
			{"rotate", func(ctx context.Context, s *secret.Service) error {
				_, err := s.Rotate(ctx, principal, "db/password")
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
		s := secret.New(newRacingRepository(), &fakeRandom{}, createOnlyAuthorizer{})
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

// putFirstRepository holds the first Get, after it has read, until a Put has
// stored or 100 ms pass, so an unguarded rotation writes over that Put.
type putFirstRepository struct {
	fakeRepository
	mu      sync.Mutex
	gets    atomic.Int32
	read    chan struct{}
	put     chan struct{}
	putOnce sync.Once
}

func newPutFirstRepository() *putFirstRepository {
	return &putFirstRepository{
		fakeRepository: fakeRepository{secrets: make(map[string]secret.Entry)},
		read:           make(chan struct{}),
		put:            make(chan struct{}),
	}
}

func (r *putFirstRepository) Put(ctx context.Context, path string, entry secret.Entry) error {
	r.mu.Lock()
	err := r.fakeRepository.Put(ctx, path, entry)
	r.mu.Unlock()

	r.putOnce.Do(func() { close(r.put) })
	return err
}

func (r *putFirstRepository) Get(ctx context.Context, path string) (secret.Entry, error) {
	r.mu.Lock()
	entry, err := r.fakeRepository.Get(ctx, path)
	r.mu.Unlock()

	if r.gets.Add(1) == 1 {
		close(r.read)
		select {
		case <-r.put:
		case <-time.After(100 * time.Millisecond):
		}
	}
	return entry, err
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
		fakeRepository: fakeRepository{secrets: make(map[string]secret.Entry)},
		arrived:        make(chan struct{}),
	}
}

func (r *racingRepository) Put(ctx context.Context, path string, entry secret.Entry) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.fakeRepository.Put(ctx, path, entry)
}

func (r *racingRepository) Get(ctx context.Context, path string) (secret.Entry, error) {
	r.mu.Lock()
	entry, err := r.fakeRepository.Get(ctx, path)
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
	return entry, err
}
