package secret_test

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/dimitrijegasic/seal-gate/internal/authorization"
	"github.com/dimitrijegasic/seal-gate/internal/secret"
)

// principal is who every call acts as; these tests do not depend on who it is.
var principal = authorization.NewEntityPrincipal("0123456789abcdef0123456789abcdef", "dev")

// fakeRepository keeps secrets in a map; err, when set, fails every call, and putErr only Put.
type fakeRepository struct {
	secrets map[string]secret.Entry
	calls   int
	err     error
	putErr  error
}

func (r *fakeRepository) Put(_ context.Context, path string, entry secret.Entry) error {
	r.calls++
	if r.err != nil {
		return r.err
	}
	if r.putErr != nil {
		return r.putErr
	}
	r.secrets[path] = entry
	return nil
}

func (r *fakeRepository) Get(_ context.Context, path string) (secret.Entry, error) {
	r.calls++
	if r.err != nil {
		return secret.Entry{}, r.err
	}
	entry, ok := r.secrets[path]
	if !ok {
		return secret.Entry{}, secret.ErrNotFound
	}
	entry.Value = bytes.Clone(entry.Value)
	return entry, nil
}

func (r *fakeRepository) Delete(_ context.Context, path string) error {
	r.calls++
	if r.err != nil {
		return r.err
	}
	delete(r.secrets, path)
	return nil
}

func (r *fakeRepository) List(_ context.Context, prefix string) ([]string, error) {
	r.calls++
	if r.err != nil {
		return nil, r.err
	}
	var paths []string
	for path := range r.secrets {
		if strings.HasPrefix(path, prefix) {
			paths = append(paths, path)
		}
	}

	slices.Sort(paths)
	return paths, nil
}

func newService(t *testing.T) (*secret.Service, *fakeRepository) {
	t.Helper()
	s, repo, _ := newAuthorizedService(t)
	return s, repo
}

// fakeAuthorizer records the last decision asked for; it allows unless err is set.
type fakeAuthorizer struct {
	principal  authorization.Principal
	resource   string
	capability authorization.Capability
	calls      int
	err        error
}

func (a *fakeAuthorizer) Authorize(_ context.Context, principal authorization.Principal, resource string, capability authorization.Capability) error {
	a.calls++
	a.principal = principal
	a.resource = resource
	a.capability = capability
	return a.err
}

func newAuthorizedService(t *testing.T) (*secret.Service, *fakeRepository, *fakeAuthorizer) {
	t.Helper()
	s, repo, _, authorizer := newGeneratingService(t)
	return s, repo, authorizer
}

// fakeRandom fills each call's bytes with the call's number, starting at 1, and keeps the last slice it returned;
// err, when set, fails every call.
type fakeRandom struct {
	calls byte
	last  []byte
	err   error
}

func (r *fakeRandom) Bytes(n int) ([]byte, error) {
	if r.err != nil {
		return nil, r.err
	}
	r.calls++
	r.last = bytes.Repeat([]byte{r.calls}, n)
	return r.last, nil
}

func newGeneratingService(t *testing.T) (*secret.Service, *fakeRepository, *fakeRandom, *fakeAuthorizer) {
	t.Helper()
	repo := &fakeRepository{secrets: make(map[string]secret.Entry)}
	random := &fakeRandom{}
	authorizer := &fakeAuthorizer{}
	return secret.New(repo, random, authorizer), repo, random, authorizer
}

func TestService(t *testing.T) {
	t.Run("a stored secret reads back", func(t *testing.T) {
		s, _ := newService(t)
		path := "db/password"

		if err := s.Put(t.Context(), principal, path, []byte("secret")); err != nil {
			t.Fatalf("Put: %v", err)
		}
		got, err := s.Get(t.Context(), principal, path)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}

		if !bytes.Equal(got, []byte("secret")) {
			t.Errorf("got %q, want %q", got, []byte("secret"))
		}
	})

	t.Run("reading a missing secret is not found", func(t *testing.T) {
		s, _ := newService(t)

		_, err := s.Get(t.Context(), principal, "missing")

		if !errors.Is(err, secret.ErrNotFound) {
			t.Errorf("got %v, want %v", err, secret.ErrNotFound)
		}
	})

	t.Run("a deleted secret is not found", func(t *testing.T) {
		s, _ := newService(t)
		path := "db/password"

		if err := s.Put(t.Context(), principal, path, []byte("secret")); err != nil {
			t.Fatalf("Put: %v", err)
		}
		if err := s.Delete(t.Context(), principal, path); err != nil {
			t.Fatalf("Delete: %v", err)
		}

		_, err := s.Get(t.Context(), principal, path)
		if !errors.Is(err, secret.ErrNotFound) {
			t.Errorf("got %v, want %v", err, secret.ErrNotFound)
		}
	})

	t.Run("listing returns the paths under a prefix", func(t *testing.T) {
		tests := []struct {
			name   string
			prefix string
			want   []string
		}{
			{"every secret", "", []string{"api-key", "db/password", "db/user"}},
			{"nested prefix", "db/", []string{"db/password", "db/user"}},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				s, _ := newService(t)

				for _, path := range []string{"api-key", "db/password", "db/user"} {
					if err := s.Put(t.Context(), principal, path, []byte("secret")); err != nil {
						t.Fatalf("Put: %v", err)
					}
				}
				got, err := s.List(t.Context(), principal, tt.prefix)
				if err != nil {
					t.Fatalf("List: %v", err)
				}

				if !slices.Equal(got, tt.want) {
					t.Errorf("got %v, want %v", got, tt.want)
				}
			})
		}
	})

	t.Run("an invalid path is refused", func(t *testing.T) {
		tests := []struct {
			name string
			path string
		}{
			{"empty path", ""},
			{"leading slash", "/db"},
			{"trailing slash", "db/"},
			{"empty segment", "db//password"},
			{"dot segment", "db/./password"},
			{"dot-dot segment", "db/../sys"},
			{"wildcard", "db/*"},
			{"non-ASCII letter", "db/pässword"},
			{"over 256 bytes", strings.Repeat("a", 257)},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				s, _ := newService(t)

				err := s.Put(t.Context(), principal, tt.path, []byte("secret"))

				if !errors.Is(err, secret.ErrInvalidPath) {
					t.Errorf("got %v, want %v", err, secret.ErrInvalidPath)
				}
			})
		}
	})

	t.Run("a valid path is accepted", func(t *testing.T) {
		tests := []struct {
			name string
			path string
		}{
			{"single segment", "api-key"},
			{"every allowed character", "Az09._-/x"},
			{"dots within a segment", "config/.env"},
			{"exactly 256 bytes", strings.Repeat("a", 256)},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				s, _ := newService(t)

				if err := s.Put(t.Context(), principal, tt.path, []byte("secret")); err != nil {
					t.Errorf("got %v, want nil", err)
				}
			})
		}
	})

	t.Run("every operation refuses an invalid path before the repository", func(t *testing.T) {
		tests := []struct {
			name string
			call func(ctx context.Context, s *secret.Service) error
		}{
			{"put", func(ctx context.Context, s *secret.Service) error {
				return s.Put(ctx, principal, "db/", []byte("secret"))
			}},
			{"get", func(ctx context.Context, s *secret.Service) error {
				_, err := s.Get(ctx, principal, "db/")
				return err
			}},
			{"delete", func(ctx context.Context, s *secret.Service) error {
				return s.Delete(ctx, principal, "db/")
			}},
			{"generate", func(ctx context.Context, s *secret.Service) error {
				_, err := s.Generate(ctx, principal, "db/", 32)
				return err
			}},
			{"rotate", func(ctx context.Context, s *secret.Service) error {
				_, err := s.Rotate(ctx, principal, "db/")
				return err
			}},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				s, repo := newService(t)

				err := tt.call(t.Context(), s)

				if !errors.Is(err, secret.ErrInvalidPath) {
					t.Errorf("err: got %v, want %v", err, secret.ErrInvalidPath)
				}
				if repo.calls != 0 {
					t.Errorf("calls: got %d, want 0", repo.calls)
				}
			})
		}
	})

	t.Run("an invalid list prefix is refused", func(t *testing.T) {
		tests := []struct {
			name   string
			prefix string
		}{
			{"no trailing slash", "db"},
			{"leading slash", "/db/"},
			{"empty segment", "db//"},
			{"dot-dot", "../"},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				s, repo := newService(t)

				_, err := s.List(t.Context(), principal, tt.prefix)

				if !errors.Is(err, secret.ErrInvalidPath) {
					t.Errorf("err: got %v, want %v", err, secret.ErrInvalidPath)
				}
				if repo.calls != 0 {
					t.Errorf("calls: got %d, want 0", repo.calls)
				}
			})
		}
	})

	t.Run("a value over the maximum size is refused", func(t *testing.T) {
		s, repo := newService(t)

		err := s.Put(t.Context(), principal, "db/password", make([]byte, secret.MaxValueSize+1))

		if !errors.Is(err, secret.ErrValueTooLarge) {
			t.Errorf("err: got %v, want %v", err, secret.ErrValueTooLarge)
		}
		if repo.calls != 0 {
			t.Errorf("calls: got %d, want 0", repo.calls)
		}
	})

	t.Run("a value up to the maximum size is accepted", func(t *testing.T) {
		tests := []struct {
			name  string
			value []byte
		}{
			{"exactly the maximum", make([]byte, secret.MaxValueSize)},
			{"empty", []byte{}},
			{"nil", nil},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				s, _ := newService(t)

				if err := s.Put(t.Context(), principal, "db/password", tt.value); err != nil {
					t.Errorf("got %v, want nil", err)
				}
			})
		}
	})

	t.Run("a generated secret has the requested length", func(t *testing.T) {
		s, _ := newService(t)

		got, err := s.Generate(t.Context(), principal, "db/password", 32)
		if err != nil {
			t.Fatalf("Generate: %v", err)
		}

		if len(got) != 32 {
			t.Errorf("got %d bytes, want 32", len(got))
		}
	})

	t.Run("a generated value comes from the random source", func(t *testing.T) {
		s, _ := newService(t)
		// fakeRandom's first call fills every byte with 1.
		want := bytes.Repeat([]byte{1}, 32)

		got, err := s.Generate(t.Context(), principal, "db/password", 32)
		if err != nil {
			t.Fatalf("Generate: %v", err)
		}

		if !bytes.Equal(got, want) {
			t.Errorf("got %x, want %x", got, want)
		}
	})

	t.Run("a generated secret reads back as its value", func(t *testing.T) {
		s, _ := newService(t)
		path := "db/password"

		want, err := s.Generate(t.Context(), principal, path, 32)
		if err != nil {
			t.Fatalf("Generate: %v", err)
		}
		got, err := s.Get(t.Context(), principal, path)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}

		if !bytes.Equal(got, want) {
			t.Errorf("got %x, want %x", got, want)
		}
	})

	t.Run("a generated secret is marked generated", func(t *testing.T) {
		s, repo := newService(t)

		if _, err := s.Generate(t.Context(), principal, "db/password", 32); err != nil {
			t.Fatalf("Generate: %v", err)
		}

		if !repo.secrets["db/password"].Generated {
			t.Error("got unmarked, want generated")
		}
	})

	t.Run("a put over a generated secret clears the mark", func(t *testing.T) {
		s, repo := newService(t)
		path := "db/password"

		if _, err := s.Generate(t.Context(), principal, path, 32); err != nil {
			t.Fatalf("Generate: %v", err)
		}
		if err := s.Put(t.Context(), principal, path, []byte("secret")); err != nil {
			t.Fatalf("Put: %v", err)
		}

		if repo.secrets[path].Generated {
			t.Error("got generated, want unmarked")
		}
	})

	t.Run("generating over an existing path is refused", func(t *testing.T) {
		s, repo := newService(t)
		repo.secrets["db/password"] = secret.Entry{Value: []byte("old")}

		_, err := s.Generate(t.Context(), principal, "db/password", 32)

		if !errors.Is(err, secret.ErrExists) {
			t.Errorf("got %v, want %v", err, secret.ErrExists)
		}
	})

	t.Run("a length outside the bounds is refused", func(t *testing.T) {
		tests := []struct {
			name   string
			length int
		}{
			{"below the minimum", secret.MinGeneratedLength - 1},
			{"zero", 0},
			{"negative", -1},
			{"above the maximum", secret.MaxValueSize + 1},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				s, repo := newService(t)

				_, err := s.Generate(t.Context(), principal, "db/password", tt.length)

				if !errors.Is(err, secret.ErrInvalidLength) {
					t.Errorf("err: got %v, want %v", err, secret.ErrInvalidLength)
				}
				if repo.calls != 0 {
					t.Errorf("calls: got %d, want 0", repo.calls)
				}
			})
		}
	})

	t.Run("a length within the bounds is accepted", func(t *testing.T) {
		tests := []struct {
			name   string
			length int
		}{
			{"exactly the minimum", secret.MinGeneratedLength},
			{"exactly the maximum", secret.MaxValueSize},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				s, _ := newService(t)

				if _, err := s.Generate(t.Context(), principal, "db/password", tt.length); err != nil {
					t.Errorf("got %v, want nil", err)
				}
			})
		}
	})

	t.Run("a random source failure reaches the caller", func(t *testing.T) {
		s, _, random, _ := newGeneratingService(t)
		randomErr := errors.New("entropy exhausted")
		random.err = randomErr

		_, err := s.Generate(t.Context(), principal, "db/password", 32)

		if !errors.Is(err, randomErr) {
			t.Errorf("got %v, want %v", err, randomErr)
		}
	})

	t.Run("a failed store of a generated secret reaches the caller", func(t *testing.T) {
		s, repo := newService(t)
		repoErr := errors.New("disk failed")
		repo.putErr = repoErr

		_, err := s.Generate(t.Context(), principal, "db/password", 32)

		if !errors.Is(err, repoErr) {
			t.Errorf("got %v, want %v", err, repoErr)
		}
	})

	t.Run("a generated value that fails to store is cleared", func(t *testing.T) {
		s, repo, random, _ := newGeneratingService(t)
		repo.putErr = errors.New("disk failed")
		want := make([]byte, 32)

		if _, err := s.Generate(t.Context(), principal, "db/password", 32); err == nil {
			t.Fatal("Generate: got nil, want an error")
		}

		if !bytes.Equal(random.last, want) {
			t.Errorf("got %x, want %x", random.last, want)
		}
	})

	t.Run("two generates racing on the same path create one secret", func(t *testing.T) {
		s := secret.New(newRacingRepository(), &fakeRandom{}, &fakeAuthorizer{})
		ctx := t.Context()

		var errs [2]error
		var wg sync.WaitGroup
		for i := range errs {
			wg.Go(func() { _, errs[i] = s.Generate(ctx, principal, "db/password", 32) })
		}
		wg.Wait()

		var exists int
		for _, err := range errs {
			switch {
			case errors.Is(err, secret.ErrExists):
				exists++
			case err != nil:
				t.Errorf("Generate: got %v, want nil or %v", err, secret.ErrExists)
			}
		}
		if exists != 1 {
			t.Errorf("got %d refused, want 1", exists)
		}
	})

	t.Run("a rotated secret has a new value", func(t *testing.T) {
		s, _ := newService(t)
		path := "db/password"

		old, err := s.Generate(t.Context(), principal, path, 32)
		if err != nil {
			t.Fatalf("Generate: %v", err)
		}
		old = bytes.Clone(old)
		got, err := s.Rotate(t.Context(), principal, path)
		if err != nil {
			t.Fatalf("Rotate: %v", err)
		}

		if bytes.Equal(got, old) {
			t.Errorf("got %x, want a value other than %x", got, old)
		}
	})

	t.Run("a rotated secret keeps its length", func(t *testing.T) {
		s, _ := newService(t)
		path := "db/password"

		if _, err := s.Generate(t.Context(), principal, path, 48); err != nil {
			t.Fatalf("Generate: %v", err)
		}
		got, err := s.Rotate(t.Context(), principal, path)
		if err != nil {
			t.Fatalf("Rotate: %v", err)
		}

		if len(got) != 48 {
			t.Errorf("got %d bytes, want 48", len(got))
		}
	})

	t.Run("a rotated secret reads back as its new value", func(t *testing.T) {
		s, _ := newService(t)
		path := "db/password"

		if _, err := s.Generate(t.Context(), principal, path, 32); err != nil {
			t.Fatalf("Generate: %v", err)
		}
		want, err := s.Rotate(t.Context(), principal, path)
		if err != nil {
			t.Fatalf("Rotate: %v", err)
		}
		got, err := s.Get(t.Context(), principal, path)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}

		if !bytes.Equal(got, want) {
			t.Errorf("got %x, want %x", got, want)
		}
	})

	t.Run("a rotated secret stays marked generated", func(t *testing.T) {
		s, repo := newService(t)
		path := "db/password"

		if _, err := s.Generate(t.Context(), principal, path, 32); err != nil {
			t.Fatalf("Generate: %v", err)
		}
		if _, err := s.Rotate(t.Context(), principal, path); err != nil {
			t.Fatalf("Rotate: %v", err)
		}

		if !repo.secrets[path].Generated {
			t.Error("got unmarked, want generated")
		}
	})

	t.Run("a secret written by put cannot be rotated", func(t *testing.T) {
		s, repo := newService(t)
		repo.secrets["db/password"] = secret.Entry{Value: []byte("secret")}

		_, err := s.Rotate(t.Context(), principal, "db/password")

		if !errors.Is(err, secret.ErrNotRotatable) {
			t.Errorf("got %v, want %v", err, secret.ErrNotRotatable)
		}
	})

	t.Run("a refused rotation keeps the stored value", func(t *testing.T) {
		s, repo := newService(t)
		want := []byte("secret")
		repo.secrets["db/password"] = secret.Entry{Value: bytes.Clone(want)}

		if _, err := s.Rotate(t.Context(), principal, "db/password"); !errors.Is(err, secret.ErrNotRotatable) {
			t.Fatalf("Rotate: got %v, want %v", err, secret.ErrNotRotatable)
		}

		if got := repo.secrets["db/password"].Value; !bytes.Equal(got, want) {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("rotating a missing secret is not found", func(t *testing.T) {
		s, _ := newService(t)

		_, err := s.Rotate(t.Context(), principal, "missing")

		if !errors.Is(err, secret.ErrNotFound) {
			t.Errorf("got %v, want %v", err, secret.ErrNotFound)
		}
	})

	t.Run("a random source failure during rotation reaches the caller", func(t *testing.T) {
		s, repo, random, _ := newGeneratingService(t)
		repo.secrets["db/password"] = secret.Entry{Value: make([]byte, 32), Generated: true}
		randomErr := errors.New("entropy exhausted")
		random.err = randomErr

		_, err := s.Rotate(t.Context(), principal, "db/password")

		if !errors.Is(err, randomErr) {
			t.Errorf("got %v, want %v", err, randomErr)
		}
	})

	t.Run("a failed store of a rotated secret reaches the caller", func(t *testing.T) {
		s, repo := newService(t)
		repo.secrets["db/password"] = secret.Entry{Value: make([]byte, 32), Generated: true}
		repoErr := errors.New("disk failed")
		repo.putErr = repoErr

		_, err := s.Rotate(t.Context(), principal, "db/password")

		if !errors.Is(err, repoErr) {
			t.Errorf("got %v, want %v", err, repoErr)
		}
	})

	t.Run("a rotated value that fails to store is cleared", func(t *testing.T) {
		s, repo, random, _ := newGeneratingService(t)
		repo.secrets["db/password"] = secret.Entry{Value: make([]byte, 32), Generated: true}
		repo.putErr = errors.New("disk failed")
		want := make([]byte, 32)

		if _, err := s.Rotate(t.Context(), principal, "db/password"); err == nil {
			t.Fatal("Rotate: got nil, want an error")
		}

		if !bytes.Equal(random.last, want) {
			t.Errorf("got %x, want %x", random.last, want)
		}
	})

	t.Run("a put racing a rotation is never overwritten", func(t *testing.T) {
		repo := newPutFirstRepository()
		repo.secrets["db/password"] = secret.Entry{Value: make([]byte, 32), Generated: true}
		s := secret.New(repo, &fakeRandom{}, &fakeAuthorizer{})
		ctx := t.Context()
		want := []byte("secret")

		var wg sync.WaitGroup
		wg.Go(func() {
			if _, err := s.Rotate(ctx, principal, "db/password"); err != nil {
				t.Errorf("Rotate: %v", err)
			}
		})
		// The put starts only once the rotation has read the secret.
		<-repo.read
		wg.Go(func() {
			if err := s.Put(ctx, principal, "db/password", want); err != nil {
				t.Errorf("Put: %v", err)
			}
		})
		wg.Wait()

		if got := repo.secrets["db/password"].Value; !bytes.Equal(got, want) {
			t.Errorf("got %x, want %x", got, want)
		}
	})

	t.Run("every operation reports sealed", func(t *testing.T) {
		for _, op := range operations {
			t.Run(op.name, func(t *testing.T) {
				s, repo := newService(t)
				repo.err = secret.ErrSealed

				err := op.call(t.Context(), s)

				if !errors.Is(err, secret.ErrSealed) {
					t.Errorf("got %v, want %v", err, secret.ErrSealed)
				}
			})
		}
	})

	t.Run("an unexpected repository failure reaches the caller", func(t *testing.T) {
		for _, op := range operations {
			t.Run(op.name, func(t *testing.T) {
				s, repo := newService(t)
				repoErr := errors.New("disk failed")
				repo.err = repoErr

				err := op.call(t.Context(), s)

				if !errors.Is(err, repoErr) {
					t.Errorf("got %v, want %v", err, repoErr)
				}
			})
		}
	})
}

// operations calls each service method with valid input, so only the repository can fail it.
var operations = []struct {
	name string
	call func(ctx context.Context, s *secret.Service) error
}{
	{"put", func(ctx context.Context, s *secret.Service) error {
		return s.Put(ctx, principal, "db/password", []byte("secret"))
	}},
	{"get", func(ctx context.Context, s *secret.Service) error {
		_, err := s.Get(ctx, principal, "db/password")
		return err
	}},
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
