package cryptography_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/dimitrijegasic/seal-gate/internal/cryptography"
)

func noopBorrow([]byte) error { return nil }

func installKey(t *testing.T, kh *cryptography.KeyHolder) []byte {
	t.Helper()
	key := newKey(t)

	err := kh.Install(key)
	if err != nil {
		t.Fatalf("Install: %v", err)
	}

	return key
}

func TestKeyHolder(t *testing.T) {
	t.Run("borrowing before any install returns ErrNoActiveKey", func(t *testing.T) {
		kh := cryptography.NewKeyHolder()

		err := kh.WithKey(noopBorrow)

		if !errors.Is(err, cryptography.ErrNoActiveKey) {
			t.Errorf("got error %v, want %v", err, cryptography.ErrNoActiveKey)
		}
	})

	t.Run("borrowing after install lends the installed key", func(t *testing.T) {
		kh := cryptography.NewKeyHolder()
		key := installKey(t, kh)

		called := false
		err := kh.WithKey(func(lentKey []byte) error {
			called = true
			if !bytes.Equal(lentKey, key) {
				t.Errorf("got lent key %x, want %x", lentKey, key)
			}
			return nil
		})

		if err != nil {
			t.Errorf("got error %v, want nil", err)
		}
		if !called {
			t.Errorf("callback was never called")
		}
	})

	t.Run("install rejects a key that is not 32 bytes", func(t *testing.T) {
		tests := []struct {
			name string
			key  []byte
		}{
			{"nil key", nil},
			{"empty key", []byte{}},
			{"AES-128 key", make([]byte, 16)},
			{"short key", make([]byte, 31)},
			{"long key", make([]byte, 33)},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				kh := cryptography.NewKeyHolder()

				err := kh.Install(tt.key)

				if !errors.Is(err, cryptography.ErrInvalidKeyLength) {
					t.Errorf("got error %v, want %v", err, cryptography.ErrInvalidKeyLength)
				}
			})
		}
	})

	t.Run("zeroing the caller's slice after install does not affect the borrowed key", func(t *testing.T) {
		kh := cryptography.NewKeyHolder()
		key := installKey(t, kh)
		want := bytes.Clone(key)

		clear(key)
		called := false
		err := kh.WithKey(func(lentKey []byte) error {
			if !bytes.Equal(lentKey, want) {
				t.Errorf("got lent key %x, want %x", lentKey, want)
			}
			called = true
			return nil
		})

		if err != nil {
			t.Fatalf("WithKey: %v", err)
		}
		if !called {
			t.Errorf("callback was never called")
		}
	})

	t.Run("borrowing after clear returns ErrNoActiveKey", func(t *testing.T) {
		kh := cryptography.NewKeyHolder()
		installKey(t, kh)

		kh.Clear()
		err := kh.WithKey(noopBorrow)

		if !errors.Is(err, cryptography.ErrNoActiveKey) {
			t.Errorf("got error %v, want %v", err, cryptography.ErrNoActiveKey)
		}
	})

	t.Run("installing over an existing key replaces it", func(t *testing.T) {
		kh := cryptography.NewKeyHolder()
		installKey(t, kh)
		key2 := installKey(t, kh)

		called := false
		err := kh.WithKey(func(lentKey []byte) error {
			if !bytes.Equal(lentKey, key2) {
				t.Errorf("got lent key %x, want %x", lentKey, key2)
			}
			called = true
			return nil
		})

		if err != nil {
			t.Fatalf("WithKey: %v", err)
		}
		if !called {
			t.Errorf("callback was never called")
		}
	})

	t.Run("IsInstalled reports the state", func(t *testing.T) {
		tests := []struct {
			name  string
			setup func(t *testing.T, kh *cryptography.KeyHolder)
			want  bool
		}{
			{"before install", func(t *testing.T, kh *cryptography.KeyHolder) {}, false},
			{"after install", func(t *testing.T, kh *cryptography.KeyHolder) {
				installKey(t, kh)
			}, true},
			{"after clear", func(t *testing.T, kh *cryptography.KeyHolder) {
				installKey(t, kh)
				kh.Clear()
			}, false},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				kh := cryptography.NewKeyHolder()
				tt.setup(t, kh)

				isInstalled := kh.IsInstalled()

				if isInstalled != tt.want {
					t.Errorf("got %v, want %v", isInstalled, tt.want)
				}
			})
		}
	})

	t.Run("WithKey returns the callback's error unchanged", func(t *testing.T) {
		callbackErr := errors.New("callback error")
		kh := cryptography.NewKeyHolder()
		installKey(t, kh)

		err := kh.WithKey(func(key []byte) error {
			return callbackErr
		})

		// == rather than not errors.Is: a wrapped error must fail.
		if err != callbackErr {
			t.Errorf("got error %v, want %v", err, callbackErr)
		}
	})

	t.Run("WithKey does not call the callback while sealed", func(t *testing.T) {
		kh := cryptography.NewKeyHolder()
		installKey(t, kh)

		called := false
		kh.Clear()
		_ = kh.WithKey(func(key []byte) error {
			called = true
			return nil
		})

		if called {
			t.Errorf("callback was called while sealed")
		}
	})
}
