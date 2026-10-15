package secret_test

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dimitrijegasic/seal-gate/internal/secret"
)

// generatedEntry is a generated secret of 32 zero bytes, rotated every hour and due at expiresAt.
func generatedEntry(expiresAt time.Time) secret.Entry {
	return secret.Entry{Value: make([]byte, 32), Generated: true, TTL: time.Hour, ExpiresAt: expiresAt}
}

// storedEntry is a secret written by put, living an hour and expiring at expiresAt.
func storedEntry(expiresAt time.Time) secret.Entry {
	return secret.Entry{Value: []byte("secret"), TTL: time.Hour, ExpiresAt: expiresAt}
}

// sweep runs one sweep that is expected to succeed and returns its report.
func sweep(t *testing.T, s *secret.Service) []secret.Action {
	t.Helper()
	actions, err := s.Sweep(t.Context())
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	return actions
}

func TestSweep(t *testing.T) {
	t.Run("a due generated secret is rotated", func(t *testing.T) {
		f := newFixture(t)
		f.repo.secrets["db/password"] = generatedEntry(f.clock.now.Add(-time.Minute))

		sweep(t, f.service)

		if got := f.repo.secrets["db/password"].Value; bytes.Equal(got, make([]byte, 32)) {
			t.Errorf("got %x, want a new value", got)
		}
	})

	t.Run("a rotated secret keeps its length", func(t *testing.T) {
		f := newFixture(t)
		f.repo.secrets["db/password"] = generatedEntry(f.clock.now.Add(-time.Minute))

		sweep(t, f.service)

		if got := len(f.repo.secrets["db/password"].Value); got != 32 {
			t.Errorf("got %d, want 32", got)
		}
	})

	t.Run("a rotation sets the next expiry from the stored TTL", func(t *testing.T) {
		f := newFixture(t)
		f.repo.secrets["db/password"] = generatedEntry(f.clock.now.Add(-time.Minute))
		want := f.clock.now.Add(time.Hour)

		sweep(t, f.service)

		if got := f.repo.secrets["db/password"].ExpiresAt; !got.Equal(want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("an expired stored secret is deleted", func(t *testing.T) {
		f := newFixture(t)
		f.repo.secrets["db/password"] = storedEntry(f.clock.now.Add(-time.Minute))

		sweep(t, f.service)

		if _, ok := f.repo.secrets["db/password"]; ok {
			t.Error("secret still stored")
		}
	})

	t.Run("a generated secret not yet due is left alone", func(t *testing.T) {
		f := newFixture(t)
		want := generatedEntry(f.clock.now.Add(time.Minute))
		f.repo.secrets["db/password"] = want

		sweep(t, f.service)

		if got := f.repo.secrets["db/password"]; !reflect.DeepEqual(got, want) {
			t.Errorf("got %+v, want %+v", got, want)
		}
	})

	t.Run("a stored secret not yet expired is left alone", func(t *testing.T) {
		f := newFixture(t)
		want := storedEntry(f.clock.now.Add(time.Minute))
		f.repo.secrets["db/password"] = want

		sweep(t, f.service)

		if got := f.repo.secrets["db/password"]; !reflect.DeepEqual(got, want) {
			t.Errorf("got %+v, want %+v", got, want)
		}
	})

	t.Run("a secret with no TTL is left alone", func(t *testing.T) {
		tests := []struct {
			name  string
			entry secret.Entry
		}{
			{"generated", secret.Entry{Value: make([]byte, 32), Generated: true}},
			{"stored", secret.Entry{Value: []byte("secret")}},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				f := newFixture(t)
				f.repo.secrets["db/password"] = tt.entry

				sweep(t, f.service)

				if got := f.repo.secrets["db/password"]; !reflect.DeepEqual(got, tt.entry) {
					t.Errorf("got %+v, want %+v", got, tt.entry)
				}
			})
		}
	})

	t.Run("a secret at its expiry exactly is acted on", func(t *testing.T) {
		tests := []struct {
			name  string
			entry func(expiresAt time.Time) secret.Entry
		}{
			{"generated", generatedEntry},
			{"stored", storedEntry},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				f := newFixture(t)
				before := tt.entry(f.clock.now)
				f.repo.secrets["db/password"] = before

				sweep(t, f.service)

				if got := f.repo.secrets["db/password"]; reflect.DeepEqual(got, before) {
					t.Errorf("got %+v, want it rotated or deleted", got)
				}
			})
		}
	})

	t.Run("the report lists each path with its action", func(t *testing.T) {
		f := newFixture(t)
		past := f.clock.now.Add(-time.Minute)
		f.repo.secrets["api/key"] = generatedEntry(past)
		f.repo.secrets["db/password"] = storedEntry(past)
		f.repo.secrets["db/user"] = storedEntry(f.clock.now.Add(time.Minute))

		got := sweep(t, f.service)

		want := []secret.Action{
			{Path: "api/key", Kind: secret.ActionRotated},
			{Path: "db/password", Kind: secret.ActionExpired},
		}
		if !slices.Equal(got, want) {
			t.Errorf("got %+v, want %+v", got, want)
		}
	})

	t.Run("a rotated value is cleared once stored", func(t *testing.T) {
		f := newFixture(t)
		f.repo.secrets["db/password"] = generatedEntry(f.clock.now.Add(-time.Minute))

		sweep(t, f.service)

		if want := make([]byte, 32); !bytes.Equal(f.random.last, want) {
			t.Errorf("got %x, want %x", f.random.last, want)
		}
	})

	t.Run("a failed list reaches the caller", func(t *testing.T) {
		f := newFixture(t)
		listErr := errors.New("disk failed")
		f.repo.err = listErr

		_, err := f.service.Sweep(t.Context())

		if !errors.Is(err, listErr) {
			t.Errorf("got %v, want %v", err, listErr)
		}
	})

	t.Run("a failed read reaches the caller", func(t *testing.T) {
		f := newFixture(t)
		f.repo.secrets["db/password"] = storedEntry(f.clock.now.Add(-time.Minute))
		getErr := errors.New("disk failed")
		f.repo.getErr = getErr

		_, err := f.service.Sweep(t.Context())

		if !errors.Is(err, getErr) {
			t.Errorf("got %v, want %v", err, getErr)
		}
	})

	t.Run("a failed action reaches the caller", func(t *testing.T) {
		failure := errors.New("failed")
		tests := []struct {
			name  string
			entry func(expiresAt time.Time) secret.Entry
			fail  func(f fixture)
		}{
			{"random source", generatedEntry, func(f fixture) { f.random.err = failure }},
			{"store", generatedEntry, func(f fixture) { f.repo.putErr = failure }},
			{"delete", storedEntry, func(f fixture) { f.repo.deleteErr = failure }},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				f := newFixture(t)
				f.repo.secrets["db/password"] = tt.entry(f.clock.now.Add(-time.Minute))
				tt.fail(f)

				_, err := f.service.Sweep(t.Context())

				if !errors.Is(err, failure) {
					t.Errorf("got %v, want %v", err, failure)
				}
			})
		}
	})

	t.Run("a failure on one path does not stop the scan", func(t *testing.T) {
		f := newFixture(t)
		past := f.clock.now.Add(-time.Minute)
		repo := &failingRepository{fakeRepository: f.repo, failGet: "api/key", err: errors.New("disk failed")}
		repo.secrets["api/key"] = storedEntry(past)
		repo.secrets["db/password"] = storedEntry(past)
		s := secret.New(repo, f.random, f.authorizer, f.clock)

		_, _ = s.Sweep(t.Context())

		if _, ok := repo.secrets["db/password"]; ok {
			t.Error("db/password still stored")
		}
	})

	t.Run("a failure names its path", func(t *testing.T) {
		tests := []struct {
			name  string
			entry func(expiresAt time.Time) secret.Entry
			fail  func(f fixture)
		}{
			{"read", storedEntry, func(f fixture) { f.repo.getErr = errors.New("failed") }},
			{"store", generatedEntry, func(f fixture) { f.repo.putErr = errors.New("failed") }},
			{"delete", storedEntry, func(f fixture) { f.repo.deleteErr = errors.New("failed") }},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				f := newFixture(t)
				f.repo.secrets["db/password"] = tt.entry(f.clock.now.Add(-time.Minute))
				tt.fail(f)

				_, err := f.service.Sweep(t.Context())

				if err == nil || !strings.Contains(err.Error(), "db/password") {
					t.Errorf("got %v, want the path named", err)
				}
			})
		}
	})

	t.Run("a secret deleted between listing and reading is skipped", func(t *testing.T) {
		f := newFixture(t)
		repo := &ghostRepository{fakeRepository: f.repo, ghost: "db/gone"}
		s := secret.New(repo, f.random, f.authorizer, f.clock)

		if _, err := s.Sweep(t.Context()); err != nil {
			t.Errorf("got %v, want nil", err)
		}
	})

	t.Run("a sealed repository is reported as sealed", func(t *testing.T) {
		tests := []struct {
			name  string
			entry func(expiresAt time.Time) secret.Entry
			seal  func(f fixture)
		}{
			{"at list", storedEntry, func(f fixture) { f.repo.err = secret.ErrSealed }},
			{"at read", storedEntry, func(f fixture) { f.repo.getErr = secret.ErrSealed }},
			{"at store", generatedEntry, func(f fixture) { f.repo.putErr = secret.ErrSealed }},
			{"at delete", storedEntry, func(f fixture) { f.repo.deleteErr = secret.ErrSealed }},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				f := newFixture(t)
				f.repo.secrets["db/password"] = tt.entry(f.clock.now.Add(-time.Minute))
				tt.seal(f)

				_, err := f.service.Sweep(t.Context())

				if !errors.Is(err, secret.ErrSealed) {
					t.Errorf("got %v, want %v", err, secret.ErrSealed)
				}
			})
		}
	})

	t.Run("sealing mid-scan stops the scan", func(t *testing.T) {
		f := newFixture(t)
		past := f.clock.now.Add(-time.Minute)
		f.repo.secrets["api/key"] = storedEntry(past)
		f.repo.secrets["db/password"] = storedEntry(past)
		f.repo.getErr = secret.ErrSealed

		_, _ = f.service.Sweep(t.Context())

		// One list, then one read: the second path is never tried.
		if f.repo.calls != 2 {
			t.Errorf("got %d calls, want 2", f.repo.calls)
		}
	})

	t.Run("a cancelled context stops the scan", func(t *testing.T) {
		f := newFixture(t)
		f.repo.secrets["db/password"] = storedEntry(f.clock.now.Add(-time.Minute))
		ctx, cancel := context.WithCancel(t.Context())
		cancel()

		_, _ = f.service.Sweep(ctx)

		if _, ok := f.repo.secrets["db/password"]; !ok {
			t.Error("secret deleted after cancellation")
		}
	})

	t.Run("a cancelled scan reports the cancellation", func(t *testing.T) {
		f := newFixture(t)
		f.repo.secrets["db/password"] = storedEntry(f.clock.now.Add(-time.Minute))
		ctx, cancel := context.WithCancel(t.Context())
		cancel()

		_, err := f.service.Sweep(ctx)

		if !errors.Is(err, context.Canceled) {
			t.Errorf("got %v, want %v", err, context.Canceled)
		}
	})

	t.Run("a put racing a due action is never undone", func(t *testing.T) {
		tests := []struct {
			name  string
			entry func(expiresAt time.Time) secret.Entry
		}{
			{"rotation", generatedEntry},
			{"expiry", storedEntry},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				clock := &fakeClock{now: time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)}
				repo := newPutFirstRepository()
				repo.secrets["db/password"] = tt.entry(clock.now.Add(-time.Minute))
				s := secret.New(repo, &fakeRandom{}, &fakeAuthorizer{}, clock)
				ctx := t.Context()
				want := []byte("new")

				var wg sync.WaitGroup
				wg.Go(func() {
					if _, err := s.Sweep(ctx); err != nil {
						t.Errorf("Sweep: %v", err)
					}
				})
				// The put starts only once the sweep has read the secret.
				<-repo.read
				wg.Go(func() {
					if err := s.Put(ctx, principal, "db/password", want, 0); err != nil {
						t.Errorf("Put: %v", err)
					}
				})
				wg.Wait()

				if got := repo.secrets["db/password"].Value; !bytes.Equal(got, want) {
					t.Errorf("got %x, want %x", got, want)
				}
			})
		}
	})
}

// ghostRepository lists one path more than it stores, as if it were deleted between List and Get.
type ghostRepository struct {
	*fakeRepository
	ghost string
}

func (r *ghostRepository) List(ctx context.Context, prefix string) ([]string, error) {
	paths, err := r.fakeRepository.List(ctx, prefix)
	return append(paths, r.ghost), err
}

// failingRepository fails Get on one path only.
type failingRepository struct {
	*fakeRepository
	failGet string
	err     error
}

func (r *failingRepository) Get(ctx context.Context, path string) (secret.Entry, error) {
	if path == r.failGet {
		return secret.Entry{}, r.err
	}
	return r.fakeRepository.Get(ctx, path)
}
