package barrier_test

import (
	"bytes"
	"errors"
	"slices"
	"testing"

	"github.com/dimitrijegasic/seal-gate/internal/barrier"
	"github.com/dimitrijegasic/seal-gate/internal/cryptography"
	"github.com/dimitrijegasic/seal-gate/internal/storage"
	"github.com/dimitrijegasic/seal-gate/internal/storage/memory"
)

func newRootKey(t *testing.T) []byte {
	t.Helper()
	key, err := cryptography.CryptoRandom{}.Bytes(32)
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}
	return key
}

func newBarrier(t *testing.T, rootKey []byte) (*barrier.AEADBarrier, storage.Backend, *cryptography.KeyHolder) {
	t.Helper()

	if rootKey == nil {
		rootKey = newRootKey(t)
	}

	keys := cryptography.NewKeyHolder()
	if err := keys.Install(rootKey); err != nil {
		t.Fatalf("Install: %v", err)
	}

	cipher, err := cryptography.NewAEADCipher("aes-256-gcm")
	if err != nil {
		t.Fatalf("NewAEADCipher: %v", err)
	}

	physical := memory.New()
	return barrier.NewAEADBarrier(physical, keys, cipher), physical, keys
}

func mustGet(t *testing.T, b *barrier.AEADBarrier, key string) []byte {
	t.Helper()

	got, err := b.Get(t.Context(), key)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	return got
}

func mustPut(t *testing.T, b *barrier.AEADBarrier, key string, value []byte) {
	t.Helper()

	if err := b.Put(t.Context(), key, value); err != nil {
		t.Fatalf("Put: %v", err)
	}
}

func mustGetRaw(t *testing.T, p storage.Backend, key string) []byte {
	t.Helper()

	got, err := p.Get(t.Context(), key)
	if err != nil {
		t.Fatalf("backend Get: %v", err)
	}
	return got
}

func mustPutRaw(t *testing.T, p storage.Backend, key string, value []byte) {
	t.Helper()

	if err := p.Put(t.Context(), key, value); err != nil {
		t.Fatalf("backend Put: %v", err)
	}
}

func TestBarrier(t *testing.T) {
	t.Run("a value put through the barrier reads back", func(t *testing.T) {
		tests := []struct {
			name  string
			value []byte
		}{
			{"nil value", nil},
			{"empty value", []byte{}},
			{"non-empty value", []byte("value")},
		}

		key := "key"
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				b, _, _ := newBarrier(t, nil)

				mustPut(t, b, key, tt.value)
				got := mustGet(t, b, key)

				if !bytes.Equal(got, tt.value) {
					t.Errorf("Get: got %q, want %q", got, tt.value)
				}
			})
		}
	})

	t.Run("the backend never sees the plaintext", func(t *testing.T) {
		b, p, _ := newBarrier(t, nil)
		key, value := "key", []byte("very secret value")

		mustPut(t, b, key, value)
		raw := mustGetRaw(t, p, key)

		if bytes.Contains(raw, value) {
			t.Errorf("raw = %x, contains %x", raw, value)
		}
	})

	t.Run("a ciphertext moved to another key does not decrypt", func(t *testing.T) {
		b, p, _ := newBarrier(t, nil)
		key1, key2, value := "key1", "key2", []byte("value")

		mustPut(t, b, key1, value)
		raw := mustGetRaw(t, p, key1)
		mustPutRaw(t, p, key2, raw)
		_, err := b.Get(t.Context(), key2)

		if !errors.Is(err, cryptography.ErrDecryptionFailed) {
			t.Errorf("Get: got %v, want %v", err, cryptography.ErrDecryptionFailed)
		}
	})

	t.Run("a tampered stored value does not decrypt", func(t *testing.T) {
		b, p, _ := newBarrier(t, nil)
		key, value := "key", []byte("value")

		mustPut(t, b, key, value)
		raw := mustGetRaw(t, p, key)
		raw[len(raw)-1] ^= 1
		mustPutRaw(t, p, key, raw)
		_, err := b.Get(t.Context(), key)

		if !errors.Is(err, cryptography.ErrDecryptionFailed) {
			t.Errorf("Get: got %v, want %v", err, cryptography.ErrDecryptionFailed)
		}
	})

	t.Run("a stored value starts with the format version", func(t *testing.T) {
		b, p, _ := newBarrier(t, nil)
		key, value := "key", []byte("value")

		mustPut(t, b, key, value)
		raw := mustGetRaw(t, p, key)

		if raw[0] != 1 {
			t.Errorf("raw[0]: got %x, want %x", raw[0], 1)
		}
	})

	t.Run("a stored value with an unknown format version does not decrypt", func(t *testing.T) {
		b, p, _ := newBarrier(t, nil)
		key, value := "key", []byte("value")

		mustPut(t, b, key, value)
		raw := mustGetRaw(t, p, key)
		raw[0] = 2
		mustPutRaw(t, p, key, raw)
		_, err := b.Get(t.Context(), key)

		if !errors.Is(err, cryptography.ErrDecryptionFailed) {
			t.Errorf("Get: got %v, want %v", err, cryptography.ErrDecryptionFailed)
		}
	})

	t.Run("an empty stored value does not decrypt", func(t *testing.T) {
		b, p, _ := newBarrier(t, nil)
		key := "key"

		mustPutRaw(t, p, key, []byte{})
		_, err := b.Get(t.Context(), key)

		if !errors.Is(err, cryptography.ErrDecryptionFailed) {
			t.Errorf("Get: got %v, want %v", err, cryptography.ErrDecryptionFailed)
		}
	})

	t.Run("getting a missing key returns ErrNotFound", func(t *testing.T) {
		b, _, _ := newBarrier(t, nil)
		key := "missing"

		_, err := b.Get(t.Context(), key)
		if !errors.Is(err, storage.ErrNotFound) {
			t.Errorf("Get: got %v, want %v", err, storage.ErrNotFound)
		}
	})

	t.Run("delete through the barrier removes the value", func(t *testing.T) {
		b, p, _ := newBarrier(t, nil)
		key, value := "key", []byte("value")

		mustPut(t, b, key, value)
		if err := b.Delete(t.Context(), key); err != nil {
			t.Fatalf("Delete: %v", err)
		}

		_, err := b.Get(t.Context(), key)
		if !errors.Is(err, storage.ErrNotFound) {
			t.Errorf("Get: got %v, want %v", err, storage.ErrNotFound)
		}

		_, err = p.Get(t.Context(), key)
		if !errors.Is(err, storage.ErrNotFound) {
			t.Errorf("backend Get: got %v, want %v", err, storage.ErrNotFound)
		}
	})

	t.Run("deleting a missing key through the barrier is not an error", func(t *testing.T) {
		b, _, _ := newBarrier(t, nil)
		key := "missing"

		if err := b.Delete(t.Context(), key); err != nil {
			t.Errorf("got %v, want nil", err)
		}
	})

	t.Run("list through the barrier returns the keys under a prefix", func(t *testing.T) {
		b, _, _ := newBarrier(t, nil)
		value := []byte("value")
		prefix := "b/"
		keys := []string{"b/2", "a/1", "b/1", "b/3"}
		want := []string{"b/1", "b/2", "b/3"}

		for _, key := range keys {
			mustPut(t, b, key, value)
		}

		got, err := b.List(t.Context(), prefix)
		if err != nil {
			t.Fatalf("List: %v", err)
		}

		if !slices.Equal(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("every operation refuses while sealed", func(t *testing.T) {
		key, value := "key", []byte("value")
		tests := []struct {
			name      string
			operation func(t *testing.T, b *barrier.AEADBarrier) error
		}{
			{"Put", func(t *testing.T, b *barrier.AEADBarrier) error {
				return b.Put(t.Context(), key, value)
			}},
			{"Get", func(t *testing.T, b *barrier.AEADBarrier) error {
				_, err := b.Get(t.Context(), key)
				return err
			}},
			{"Delete", func(t *testing.T, b *barrier.AEADBarrier) error {
				return b.Delete(t.Context(), key)
			}},
			{"List", func(t *testing.T, b *barrier.AEADBarrier) error {
				_, err := b.List(t.Context(), "")
				return err
			}},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				b, _, k := newBarrier(t, nil)

				k.Clear()
				err := tt.operation(t, b)

				if !errors.Is(err, barrier.ErrSealed) {
					t.Errorf("got %v, want %v", err, barrier.ErrSealed)
				}
			})
		}
	})

	t.Run("a put refused while sealed writes nothing below", func(t *testing.T) {
		b, p, k := newBarrier(t, nil)
		key, value := "key", []byte("value")

		k.Clear()
		_ = b.Put(t.Context(), key, value)
		_, err := p.Get(t.Context(), key)

		if !errors.Is(err, storage.ErrNotFound) {
			t.Errorf("backend Get: got %v, want %v", err, storage.ErrNotFound)
		}
	})

	t.Run("a delete refused while sealed removes nothing below", func(t *testing.T) {
		b, p, k := newBarrier(t, nil)
		key, value := "key", []byte("value")

		mustPut(t, b, key, value)
		k.Clear()
		_ = b.Delete(t.Context(), key)
		_, err := p.Get(t.Context(), key)

		if err != nil {
			t.Errorf("backend Get: got %v, want %v", err, nil)
		}
	})

	t.Run("getting a missing key while sealed reports sealed, not not-found", func(t *testing.T) {
		b, _, k := newBarrier(t, nil)
		key := "missing"

		k.Clear()
		_, err := b.Get(t.Context(), key)

		if !errors.Is(err, barrier.ErrSealed) {
			t.Errorf("Get: got %v, want %v", err, barrier.ErrSealed)
		}
	})

	t.Run("a value reads back after seal and unseal with the same key", func(t *testing.T) {
		rootKey := newRootKey(t)
		b, _, k := newBarrier(t, rootKey)
		key, value := "key", []byte("value")

		mustPut(t, b, key, value)
		k.Clear()
		if err := k.Install(rootKey); err != nil {
			t.Fatalf("Install: %v", err)
		}
		got, err := b.Get(t.Context(), key)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}

		if !bytes.Equal(got, value) {
			t.Errorf("got %q, want %q", got, value)
		}
	})

	t.Run("a value does not decrypt under a different barrier key", func(t *testing.T) {
		rootKey1 := newRootKey(t)
		rootKey2 := newRootKey(t)
		b, _, k := newBarrier(t, rootKey1)
		key, value := "key", []byte("value")

		mustPut(t, b, key, value)
		k.Clear()
		if err := k.Install(rootKey2); err != nil {
			t.Fatalf("Install: %v", err)
		}
		_, err := b.Get(t.Context(), key)

		if !errors.Is(err, cryptography.ErrDecryptionFailed) {
			t.Errorf("Get: got %v, want %v", err, cryptography.ErrDecryptionFailed)
		}
	})
}
