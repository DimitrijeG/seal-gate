package secret_test

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/dimitrijegasic/seal-gate/internal/secret"
)

// fakeRepository keeps secrets in a map; err, when set, fails every call.
type fakeRepository struct {
	secrets map[string][]byte
	calls   int
	err     error
}

func (r *fakeRepository) Put(_ context.Context, path string, value []byte) error {
	r.calls++
	if r.err != nil {
		return r.err
	}
	r.secrets[path] = value
	return nil
}

func (r *fakeRepository) Get(_ context.Context, path string) ([]byte, error) {
	r.calls++
	if r.err != nil {
		return nil, r.err
	}
	value, ok := r.secrets[path]
	if !ok {
		return nil, secret.ErrNotFound
	}
	return value, nil
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
	repo := &fakeRepository{secrets: make(map[string][]byte)}
	return secret.New(repo), repo
}

func TestService(t *testing.T) {
	t.Run("a stored secret reads back", func(t *testing.T) {
		s, _ := newService(t)
		path := "db/password"

		if err := s.Put(t.Context(), path, []byte("secret")); err != nil {
			t.Fatalf("Put: %v", err)
		}
		got, err := s.Get(t.Context(), path)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}

		if !bytes.Equal(got, []byte("secret")) {
			t.Errorf("got %q, want %q", got, []byte("secret"))
		}
	})

	t.Run("reading a missing secret is not found", func(t *testing.T) {
		s, _ := newService(t)

		_, err := s.Get(t.Context(), "missing")

		if !errors.Is(err, secret.ErrNotFound) {
			t.Errorf("got %v, want %v", err, secret.ErrNotFound)
		}
	})

	t.Run("a deleted secret is not found", func(t *testing.T) {
		s, _ := newService(t)
		path := "db/password"

		if err := s.Put(t.Context(), path, []byte("secret")); err != nil {
			t.Fatalf("Put: %v", err)
		}
		if err := s.Delete(t.Context(), path); err != nil {
			t.Fatalf("Delete: %v", err)
		}

		_, err := s.Get(t.Context(), path)
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
					if err := s.Put(t.Context(), path, []byte("secret")); err != nil {
						t.Fatalf("Put: %v", err)
					}
				}
				got, err := s.List(t.Context(), tt.prefix)
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

				err := s.Put(t.Context(), tt.path, []byte("secret"))

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

				if err := s.Put(t.Context(), tt.path, []byte("secret")); err != nil {
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
				return s.Put(ctx, "db/", []byte("secret"))
			}},
			{"get", func(ctx context.Context, s *secret.Service) error {
				_, err := s.Get(ctx, "db/")
				return err
			}},
			{"delete", func(ctx context.Context, s *secret.Service) error {
				return s.Delete(ctx, "db/")
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

				_, err := s.List(t.Context(), tt.prefix)

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

		err := s.Put(t.Context(), "db/password", make([]byte, secret.MaxValueSize+1))

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

				if err := s.Put(t.Context(), "db/password", tt.value); err != nil {
					t.Errorf("got %v, want nil", err)
				}
			})
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
		return s.Put(ctx, "db/password", []byte("secret"))
	}},
	{"get", func(ctx context.Context, s *secret.Service) error {
		_, err := s.Get(ctx, "db/password")
		return err
	}},
	{"delete", func(ctx context.Context, s *secret.Service) error {
		return s.Delete(ctx, "db/password")
	}},
	{"list", func(ctx context.Context, s *secret.Service) error {
		_, err := s.List(ctx, "db/")
		return err
	}},
}
