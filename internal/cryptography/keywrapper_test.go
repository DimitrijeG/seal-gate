package cryptography_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/dimitrijegasic/seal-gate/internal/cryptography"
)

// wrapNewKey wraps a fresh random key and fails the test if wrapping fails.
func wrapNewKey(t *testing.T, kw *cryptography.KeyWrapper, wrappingKey, ad []byte) (key, wrappedKey []byte) {
	t.Helper()
	key = newKey(t)
	wrappedKey, err := kw.Wrap(wrappingKey, key, ad)
	if err != nil {
		t.Fatalf("Wrap failed: %v", err)
	}
	return key, wrappedKey
}

func TestKeyWrapper(t *testing.T) {
	t.Run("unwrapping a wrapped key returns the original key", func(t *testing.T) {
		kw := cryptography.NewKeyWrapper(newCipher(t))
		wrappingKey := newKey(t)
		ad := []byte("root-wrap/v1")
		key, wrappedKey := wrapNewKey(t, kw, wrappingKey, ad)

		got, err := kw.Unwrap(wrappingKey, wrappedKey, ad)
		if err != nil {
			t.Fatalf("Unwrap failed: %v", err)
		}

		if !bytes.Equal(got, key) {
			t.Errorf("Unwrap = %x, want %x", got, key)
		}
	})

	t.Run("wrapped key does not contain the key", func(t *testing.T) {
		kw := cryptography.NewKeyWrapper(newCipher(t))
		wrappingKey := newKey(t)
		ad := []byte("root-wrap/v1")
		key, wrappedKey := wrapNewKey(t, kw, wrappingKey, ad)

		if bytes.Contains(wrappedKey, key) {
			t.Errorf("wrapped key contains the key")
		}
	})

	t.Run("unwrap rejects bad input", func(t *testing.T) {
		kw := cryptography.NewKeyWrapper(newCipher(t))
		wrappingKey := newKey(t)
		ad := []byte("root-wrap/v1")
		_, wrappedKey := wrapNewKey(t, kw, wrappingKey, ad)

		tests := []struct {
			name                        string
			wrappingKey, wrappedKey, ad []byte
		}{
			{"different wrapping key", newKey(t), wrappedKey, ad},
			{"different additional data", wrappingKey, wrappedKey, []byte("root-wrap/v2")},
			{"tampered wrapped key", wrappingKey, flip(wrappedKey, 0), ad},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				_, err := kw.Unwrap(tt.wrappingKey, tt.wrappedKey, tt.ad)
				if err == nil {
					t.Errorf("Unwrap error = nil, want an error")
				}
			})
		}
	})

	t.Run("wrap rejects a key that is not 32 bytes", func(t *testing.T) {
		kw := cryptography.NewKeyWrapper(newCipher(t))
		wrappingKey := newKey(t)
		ad := []byte("root-wrap/v1")

		tests := []struct {
			name string
			key  []byte
		}{
			{"nil key", nil},
			{"empty key", []byte{}},
			{"key too short", make([]byte, 31)},
			{"key too long", make([]byte, 33)},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				_, err := kw.Wrap(wrappingKey, tt.key, ad)
				if !errors.Is(err, cryptography.ErrInvalidKeyLength) {
					t.Errorf("Wrap error = %v, want %v", err, cryptography.ErrInvalidKeyLength)
				}
			})
		}
	})

	t.Run("wrap rejects a wrapping key that is not 32 bytes", func(t *testing.T) {
		kw := cryptography.NewKeyWrapper(newCipher(t))
		ad := []byte("root-wrap/v1")

		tests := []struct {
			name        string
			wrappingKey []byte
		}{
			{"nil wrapping key", nil},
			{"empty wrapping key", []byte{}},
			{"wrapping key too short", make([]byte, 31)},
			{"wrapping key too long", make([]byte, 33)},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				_, err := kw.Wrap(tt.wrappingKey, newKey(t), ad)
				if !errors.Is(err, cryptography.ErrInvalidKeyLength) {
					t.Errorf("Wrap error = %v, want %v", err, cryptography.ErrInvalidKeyLength)
				}
			})
		}
	})

	t.Run("unwrap rejects a wrapped key too short to be one", func(t *testing.T) {
		kw := cryptography.NewKeyWrapper(newCipher(t))
		wrappingKey := newKey(t)
		ad := []byte("root-wrap/v1")

		tests := []struct {
			name       string
			wrappedKey []byte
		}{
			{"nil wrapped key", nil},
			{"empty wrapped key", []byte{}},
			{"wrapped key too short", make([]byte, 27)},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				_, err := kw.Unwrap(wrappingKey, tt.wrappedKey, ad)
				if err == nil {
					t.Errorf("Unwrap error = nil, want an error")
				}
			})
		}
	})

	t.Run("unwrap rejects a payload that decrypts to the wrong length", func(t *testing.T) {
		cipher := newCipher(t)
		kw := cryptography.NewKeyWrapper(cipher)
		wrappingKey := newKey(t)
		ad := []byte("root-wrap/v1")

		payload := make([]byte, 31)
		ciphertext, err := cipher.Encrypt(wrappingKey, payload, ad)
		if err != nil {
			t.Fatalf("Encrypt failed: %v", err)
		}

		_, err = kw.Unwrap(wrappingKey, ciphertext, ad)
		if !errors.Is(err, cryptography.ErrInvalidKeyLength) {
			t.Errorf("Unwrap error = %v, want %v", err, cryptography.ErrInvalidKeyLength)
		}
	})
}
