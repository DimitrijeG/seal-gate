package cryptography

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
)

const keyLen = 32

var (
	errNotImplemented       = errors.New("cryptography: not implemented")
	ErrUnsupportedAlgorithm = errors.New("cryptography: unsupported algorithm")
	ErrInvalidKeyLength     = errors.New("cryptography: invalid key length")
)

// Cipher is authenticated encryption whose output carries everything needed to
// decrypt except the key and the additional data.
type Cipher interface {
	Encrypt(key, plaintext, additionalData []byte) ([]byte, error)
	Decrypt(key, ciphertext, additionalData []byte) ([]byte, error)
}

var ciphers = map[string]func() Cipher{
	"aes-256-gcm": func() Cipher { return &aes256GCM{} },
}

// NewAEADCipher returns the Cipher for algorithm; only "aes-256-gcm" is supported.
func NewAEADCipher(algorithm string) (Cipher, error) {
	newCipher, ok := ciphers[algorithm]
	if !ok {
		return nil, fmt.Errorf("%w %q", ErrUnsupportedAlgorithm, algorithm)
	}
	return newCipher(), nil
}

// aes256GCM is AES-256 in GCM mode; each ciphertext is a random 12-byte nonce,
// the encrypted body, and a 16-byte tag.
type aes256GCM struct{}

var _ Cipher = (*aes256GCM)(nil)

func newAEAD(key []byte) (cipher.AEAD, error) {
	if len(key) != keyLen {
		return nil, ErrInvalidKeyLength
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("cryptography: %w", err)
	}

	gcm, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return nil, fmt.Errorf("cryptography: %w", err)
	}

	return gcm, nil
}

func (c *aes256GCM) Encrypt(key, plaintext, additionalData []byte) ([]byte, error) {
	gcm, err := newAEAD(key)
	if err != nil {
		return nil, err
	}

	return gcm.Seal(nil, nil, plaintext, additionalData), nil
}

func (c *aes256GCM) Decrypt(key, ciphertext, additionalData []byte) ([]byte, error) {
	gcm, err := newAEAD(key)
	if err != nil {
		return nil, err
	}

	plaintext, err := gcm.Open(nil, nil, ciphertext, additionalData)
	if err != nil {
		return nil, fmt.Errorf("cryptography: %w", err)
	}

	return plaintext, nil
}
