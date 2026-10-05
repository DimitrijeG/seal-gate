package cryptography

// KeyWrapper encrypts one 32-byte key under another.
type KeyWrapper struct {
	cipher Cipher
}

func NewKeyWrapper(cipher Cipher) *KeyWrapper {
	return &KeyWrapper{cipher: cipher}
}

// Wrap returns ErrInvalidKeyLength unless both keys are 32 bytes.
// additionalData is authenticated, not encrypted, and Unwrap must be given the same.
func (kw *KeyWrapper) Wrap(wrappingKey []byte, key []byte, additionalData []byte) ([]byte, error) {
	if len(key) != keyLen {
		return nil, ErrInvalidKeyLength
	}

	return kw.cipher.Encrypt(wrappingKey, key, additionalData)
}

// Unwrap fails if the wrapping key, additionalData or wrappedKey do not match what Wrap was given.
// The caller owns the returned key and must clear it.
func (kw *KeyWrapper) Unwrap(wrappingKey []byte, wrappedKey []byte, additionalData []byte) ([]byte, error) {
	key, err := kw.cipher.Decrypt(wrappingKey, wrappedKey, additionalData)
	if err != nil {
		return nil, err
	}

	if len(key) != keyLen {
		clear(key)
		return nil, ErrInvalidKeyLength
	}

	return key, nil
}
