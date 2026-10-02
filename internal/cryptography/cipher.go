package cryptography

import (
	"errors"
	"fmt"
)

var errNotImplemented = errors.New("cryptography: not implemented")

type Cipher interface {
	Encrypt(key, plaintext, additionalData []byte) ([]byte, error)
	Decrypt(key, ciphertext, additionalData []byte) ([]byte, error)
}

var ciphers = map[string]func() Cipher{
	"aes-256-gcm": func() Cipher { return &AES256GCM{} },
}

func NewAEADCipher(algorithm string) (Cipher, error) {
	newCipher, ok := ciphers[algorithm]
	if !ok {
		return nil, fmt.Errorf("cryptography: unsupported algorithm %q", algorithm)
	}
	return newCipher(), nil
}

type AES256GCM struct{}

func (c *AES256GCM) Encrypt(key, plaintext, additionalData []byte) ([]byte, error) {
	return nil, errNotImplemented
}

func (c *AES256GCM) Decrypt(key, ciphertext, additionalData []byte) ([]byte, error) {
	return nil, errNotImplemented
}
