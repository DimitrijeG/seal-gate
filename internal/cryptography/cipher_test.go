package cryptography_test

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/dimitrijegasic/seal-gate/internal/cryptography"
)

func newCipher(t *testing.T) cryptography.Cipher {
	t.Helper()
	c, err := cryptography.NewAEADCipher("aes-256-gcm")
	if err != nil {
		t.Fatalf("failed to create cipher: %v", err)
	}
	return c
}

func newKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("failed to generate random key: %v", err)
	}
	return key
}

func flip(data []byte, index int) []byte {
	clone := bytes.Clone(data)
	clone[index] ^= 1
	return clone
}

func TestAES256GCM(t *testing.T) {
	t.Run("decrypt returns the original plaintext", func(t *testing.T) {
		c, key := newCipher(t), newKey(t)
		plaintext, ad := []byte("top secret"), []byte("secret/db/password")

		ct, err := c.Encrypt(key, plaintext, ad)
		if err != nil {
			t.Fatalf("Encrypt failed: %v", err)
		}

		got, err := c.Decrypt(key, ct, ad)
		if err != nil {
			t.Fatalf("Decrypt failed: %v", err)
		}

		if !bytes.Equal(got, plaintext) {
			t.Errorf("Decrypt = %q, want %q", got, plaintext)
		}
	})

	t.Run("ciphertext hides the plaintext and adds nonce and tag", func(t *testing.T) {
		c, key := newCipher(t), newKey(t)
		plaintext, ad := []byte("top secret"), []byte("secret/db/password")

		ct, err := c.Encrypt(key, plaintext, ad)
		if err != nil {
			t.Fatalf("Encrypt failed: %v", err)
		}

		const overhead = 12 + 16 // nonce + tag
		if got, want := len(ct), len(plaintext)+overhead; got != want {
			t.Errorf("len(ciphertext) = %d, want %d", got, want)
		}

		if bytes.Contains(ct, plaintext) {
			t.Errorf("ciphertext contains the plaintext")
		}
	})

	t.Run("encrypting the same plaintext twice produces different ciphertexts", func(t *testing.T) {
		c, key := newCipher(t), newKey(t)
		plaintext, ad := []byte("top secret"), []byte("secret/db/password")

		ct1, err := c.Encrypt(key, plaintext, ad)
		if err != nil {
			t.Fatalf("Encrypt failed: %v", err)
		}

		ct2, err := c.Encrypt(key, plaintext, ad)
		if err != nil {
			t.Fatalf("Encrypt failed: %v", err)
		}

		if bytes.Equal(ct1, ct2) {
			t.Errorf("encrypting the same plaintext twice produced the same ciphertext")
		}
	})

	t.Run("decrypt rejects", func(t *testing.T) {
		c, key := newCipher(t), newKey(t)
		plaintext, ad := []byte("top secret"), []byte("secret/db/password")

		ct, err := c.Encrypt(key, plaintext, ad)
		if err != nil {
			t.Fatalf("Encrypt failed: %v", err)
		}

		tests := []struct {
			name string
			key  []byte
			ct   []byte
			ad   []byte
		}{
			{"a different key", newKey(t), ct, ad},
			{"a different additional data", key, ct, []byte("secret/other")},
			{"missing additional data", key, ct, nil},
			{"a flipped bit in the nonce", key, flip(ct, 0), ad},
			{"a flipped bit in the body", key, flip(ct, 12), ad},
			{"a flipped bit in the tag", key, flip(ct, len(ct)-1), ad},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				if _, err := c.Decrypt(tt.key, tt.ct, tt.ad); err == nil {
					t.Errorf("Decrypt succeeded, want an error")
				}
			})
		}
	})

	t.Run("decrypt rejects input too short to be a ciphertext", func(t *testing.T) {
		c, key := newCipher(t), newKey(t)

		tests := []struct {
			name string
			ct   []byte
		}{
			{"nil ciphertext", nil},
			{"empty ciphertext", []byte{}},
			{"ciphertext shorter than a nonce", make([]byte, 11)},
			{"ciphertext one byte short of nonce and tag", make([]byte, 27)},
			{"ciphertext exactly nonce and tag length but no body", make([]byte, 28)},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				if _, err := c.Decrypt(key, tt.ct, nil); err == nil {
					t.Errorf("Decrypt succeeded, want an error")
				}
			})
		}
	})

	t.Run("rejects keys that are not 32 bytes", func(t *testing.T) {
		c := newCipher(t)

		tests := []struct {
			name string
			key  []byte
		}{
			{"nil key", nil},
			{"empty key", []byte{}},
			{"key of length 16", make([]byte, 16)},
			{"key of length 24", make([]byte, 24)},
			{"key of length 31", make([]byte, 31)},
			{"key of length 33", make([]byte, 33)},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				if _, err := c.Encrypt(tt.key, nil, nil); !errors.Is(err, cryptography.ErrInvalidKeyLength) {
					t.Errorf("Encrypt error = %v, want ErrInvalidKeyLength", err)
				}

				if _, err := c.Decrypt(tt.key, nil, nil); !errors.Is(err, cryptography.ErrInvalidKeyLength) {
					t.Errorf("Decrypt error = %v, want ErrInvalidKeyLength", err)
				}
			})
		}
	})

	t.Run("round trip with edge cases", func(t *testing.T) {
		tests := []struct {
			name string
			pt   []byte
			ad   []byte
		}{
			{"empty plaintext with non empty additional data", []byte{}, []byte("secret/db/password")},
			{"nil plaintext and non empty additional data", nil, []byte("secret/db/password")},
			{"empty additional data with valid plaintext", []byte("top secret"), []byte{}},
			{"nil additional data with valid plaintext", []byte("top secret"), nil},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				c, key := newCipher(t), newKey(t)

				ct, err := c.Encrypt(key, tt.pt, tt.ad)
				if err != nil {
					t.Fatalf("Encrypt failed: %v", err)
				}

				got, err := c.Decrypt(key, ct, tt.ad)
				if err != nil {
					t.Fatalf("Decrypt failed: %v", err)
				}

				if !bytes.Equal(got, tt.pt) {
					t.Errorf("Decrypt = %q, want %q", got, tt.pt)
				}
			})
		}
	})

	t.Run("NewAEADCipher rejects unsupported algorithms", func(t *testing.T) {
		_, err := cryptography.NewAEADCipher("unsupported")
		if !errors.Is(err, cryptography.ErrUnsupportedAlgorithm) {
			t.Errorf("NewAEADCipher error = %v, want ErrUnsupportedAlgorithm", err)
		}
	})
}
