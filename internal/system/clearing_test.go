package system_test

import (
	"bytes"
	"errors"
	"slices"
	"testing"

	"github.com/dimitrijegasic/seal-gate/internal/system"
)

// keyLen is what the keyring asks Bytes for; the fakes would work with any length.
const keyLen = 32

// errFake is what a collaborator fails with; the rows name which one.
var errFake = errors.New("collaborator failed")

// retainingPorts are the keyring's collaborators, each keeping the very slices it
// handed over so a test can check they were cleared.
type retainingPorts struct {
	repo    *fakeRepository
	random  *retainingRandom
	sharing *retainingSharing
	wrapper *retainingWrapper
	active  *fakeController
}

func newRetainingService(t *testing.T) (*system.Service, *retainingPorts) {
	t.Helper()
	p := &retainingPorts{
		repo:    &fakeRepository{},
		random:  &retainingRandom{},
		sharing: &retainingSharing{},
		wrapper: &retainingWrapper{},
		active:  &fakeController{},
	}
	keyring := system.NewKeyring(p.repo, p.sharing, p.wrapper, p.random, p.active)
	return system.NewService(keyring, fakeClock{now: initTime}, &fakeTimer{}, &fakeAuthorizer{}, &fakeResource{active: p.active}), p
}

// newInitializedRetainingService returns a service past init with the shares it
// handed out, so a row can reach unlock.
func newInitializedRetainingService(t *testing.T) (*system.Service, *retainingPorts, [][]byte) {
	t.Helper()
	s, p := newRetainingService(t)
	result, err := s.Init(t.Context(), sealConfig)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	return s, p, result.Shares
}

// unsealToThreshold returns the error from the submission that reaches the
// threshold; the ones before it must succeed.
func unsealToThreshold(t *testing.T, s *system.Service, shares [][]byte) error {
	t.Helper()
	last := sealConfig.Threshold - 1
	unsealWith(t, s, shares[:last])

	_, err := s.Unseal(t.Context(), shares[last])
	return err
}

type retainingRandom struct {
	returned [][]byte
	calls    int
	failAt   int // the 1-based call that fails; 0 never fails
}

// Bytes retains the slice it returns, never a copy, and fills it with a non-zero
// pattern; a copy or zeroes would pass a keyring that clears nothing.
func (r *retainingRandom) Bytes(n int) ([]byte, error) {
	r.calls++
	if r.calls == r.failAt {
		return nil, errFake
	}

	key := bytes.Repeat([]byte{byte(len(r.returned) + 1)}, n)
	r.returned = append(r.returned, key)
	return key, nil
}

type retainingSharing struct {
	split        [][]byte
	combined     []byte
	combinedWith [][]byte
	splitErr     error
	combineErr   error
}

func (s *retainingSharing) Split(_ []byte, shares, _ int) ([][]byte, error) {
	if s.splitErr != nil {
		return nil, s.splitErr
	}

	s.split = fakeShares(shares)
	return s.split, nil
}

func (s *retainingSharing) Combine(shares [][]byte) ([]byte, error) {
	// As given: these are the buffer's own slices, and the buffer is what clears them.
	s.combinedWith = shares
	if s.combineErr != nil {
		return nil, s.combineErr
	}

	s.combined = bytes.Repeat([]byte{0xcc}, keyLen)
	return s.combined, nil
}

// fakeShares returns n distinct non-zero shares, so a test can tell cleared from returned.
func fakeShares(n int) [][]byte {
	shares := make([][]byte, n)
	for i := range shares {
		shares[i] = bytes.Repeat([]byte{byte(i + 1)}, keyLen+1)
	}
	return shares
}

type retainingWrapper struct {
	unwrapped []byte
	wrapErr   error
	unwrapErr error
}

func (w *retainingWrapper) Wrap(_, _, _ []byte) ([]byte, error) {
	if w.wrapErr != nil {
		return nil, w.wrapErr
	}

	return []byte("wrapped"), nil
}

func (w *retainingWrapper) Unwrap(_, _, _ []byte) ([]byte, error) {
	if w.unwrapErr != nil {
		return nil, w.unwrapErr
	}

	w.unwrapped = bytes.Repeat([]byte{0xbb}, keyLen)
	return w.unwrapped, nil
}

// fakeController clones on Install, as KeyHolder does, so the caller may zero its copy.
type fakeController struct {
	key        []byte
	installErr error
}

func (c *fakeController) Install(key []byte) error {
	if c.installErr != nil {
		return c.installErr
	}

	c.key = bytes.Clone(key)
	return nil
}

func (c *fakeController) Clear() {
	clear(c.key)
	c.key = nil
}

func (c *fakeController) IsInstalled() bool { return c.key != nil }

// assertCleared fails on an empty slice too: a collaborator never called retains
// nothing, which a byte comparison alone would accept.
func assertCleared(t *testing.T, got []byte) {
	t.Helper()
	if len(got) == 0 {
		t.Errorf("got %v, want a retained slice", got)
		return
	}
	if !bytes.Equal(got, make([]byte, len(got))) {
		t.Errorf("got %x, want all zero", got)
	}
}

// assertAllCleared checks the count first: fewer slices than the path hands over
// means it was never taken, which the per-slice check would pass.
func assertAllCleared(t *testing.T, got [][]byte, want int) {
	t.Helper()
	if len(got) != want {
		t.Fatalf("got %d slices, want %d", len(got), want)
	}
	// Each fake fills its slices with a distinct pattern, so %x names the one that failed.
	for _, s := range got {
		assertCleared(t, s)
	}
}

func TestKeyClearing(t *testing.T) {
	t.Run("init clears every key it generated, whatever the outcome", func(t *testing.T) {
		tests := []struct {
			name     string
			inject   func(p *retainingPorts)
			wantErr  error
			wantKeys int
		}{
			{"init succeeds", func(*retainingPorts) {}, nil, 2},
			{"the second random read fails", func(p *retainingPorts) { p.random.failAt = 2 }, errFake, 1},
			{"the token read fails", func(p *retainingPorts) { p.random.failAt = 3 }, errFake, 2},
			{"the wrap fails", func(p *retainingPorts) { p.wrapper.wrapErr = errFake }, errFake, 2},
			{"the split fails", func(p *retainingPorts) { p.sharing.splitErr = errFake }, errFake, 2},
			{"the save fails", func(p *retainingPorts) { p.repo.saveErr = errFake }, errFake, 2},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				s, p := newRetainingService(t)
				tt.inject(p)

				_, err := s.Init(t.Context(), sealConfig)
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("Init: got %v, want %v", err, tt.wantErr)
				}

				// The third read is the root token, handed out on success.
				keys := p.random.returned[:min(len(p.random.returned), 2)]
				assertAllCleared(t, keys, tt.wantKeys)
			})
		}
	})

	t.Run("init clears the root token when it fails after generating it", func(t *testing.T) {
		tests := []struct {
			name   string
			inject func(p *retainingPorts)
		}{
			{"the wrap fails", func(p *retainingPorts) { p.wrapper.wrapErr = errFake }},
			{"the split fails", func(p *retainingPorts) { p.sharing.splitErr = errFake }},
			{"the save fails", func(p *retainingPorts) { p.repo.saveErr = errFake }},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				s, p := newRetainingService(t)
				tt.inject(p)

				_, err := s.Init(t.Context(), sealConfig)
				if !errors.Is(err, errFake) {
					t.Fatalf("Init: got %v, want %v", err, errFake)
				}
				if len(p.random.returned) < 3 {
					t.Fatalf("got %d random reads, want 3", len(p.random.returned))
				}

				assertCleared(t, p.random.returned[2])
			})
		}
	})

	t.Run("init returns the shares it generated", func(t *testing.T) {
		s, _ := newRetainingService(t)
		want := fakeShares(sealConfig.Shares)

		result, err := s.Init(t.Context(), sealConfig)
		if err != nil {
			t.Fatalf("Init: %v", err)
		}

		if !slices.EqualFunc(result.Shares, want, bytes.Equal) {
			t.Errorf("got %x, want %x", result.Shares, want)
		}
	})

	t.Run("init clears the shares when the save fails", func(t *testing.T) {
		s, p := newRetainingService(t)
		p.repo.saveErr = errFake

		_, err := s.Init(t.Context(), sealConfig)
		if !errors.Is(err, errFake) {
			t.Fatalf("Init: got %v, want %v", err, errFake)
		}

		assertAllCleared(t, p.sharing.split, sealConfig.Shares)
	})

	t.Run("unseal clears the root key it reconstructed, whatever the outcome", func(t *testing.T) {
		tests := []struct {
			name    string
			inject  func(p *retainingPorts)
			wantErr error
		}{
			{"unseal succeeds", func(*retainingPorts) {}, nil},
			{"the unwrap fails", func(p *retainingPorts) { p.wrapper.unwrapErr = errFake }, system.ErrInvalidShare},
			{"the install fails", func(p *retainingPorts) { p.active.installErr = errFake }, errFake},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				s, p, shares := newInitializedRetainingService(t)
				tt.inject(p)

				err := unsealToThreshold(t, s, shares)
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("Unseal: got %v, want %v", err, tt.wantErr)
				}

				assertCleared(t, p.sharing.combined)
			})
		}
	})

	t.Run("unseal clears the barrier key it unwrapped, whatever the outcome", func(t *testing.T) {
		tests := []struct {
			name    string
			inject  func(p *retainingPorts)
			wantErr error
		}{
			{"unseal succeeds", func(*retainingPorts) {}, nil},
			{"the install fails", func(p *retainingPorts) { p.active.installErr = errFake }, errFake},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				s, p, shares := newInitializedRetainingService(t)
				tt.inject(p)

				err := unsealToThreshold(t, s, shares)
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("Unseal: got %v, want %v", err, tt.wantErr)
				}

				assertCleared(t, p.wrapper.unwrapped)
			})
		}
	})

	t.Run("unseal clears the buffered shares, whatever the outcome", func(t *testing.T) {
		tests := []struct {
			name    string
			inject  func(p *retainingPorts)
			wantErr error
		}{
			{"unseal succeeds", func(*retainingPorts) {}, nil},
			{"the reconstruction fails", func(p *retainingPorts) { p.sharing.combineErr = errFake }, system.ErrInvalidShare},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				s, p, shares := newInitializedRetainingService(t)
				tt.inject(p)

				err := unsealToThreshold(t, s, shares)
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("Unseal: got %v, want %v", err, tt.wantErr)
				}

				assertAllCleared(t, p.sharing.combinedWith, sealConfig.Threshold)
			})
		}
	})
}
