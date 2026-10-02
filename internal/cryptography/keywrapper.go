package cryptography

type KeyWrapper struct{}

func NewKeyWrapper() *KeyWrapper {
	return &KeyWrapper{}
}

func (kw *KeyWrapper) Wrap(wrappingKey []byte, key []byte, additionalData []byte) ([]byte, error) {
	return nil, errNotImplemented
}

func (kw *KeyWrapper) Unwrap(wrappingKey []byte, wrappedKey []byte, additionalData []byte) ([]byte, error) {
	return nil, errNotImplemented
}
