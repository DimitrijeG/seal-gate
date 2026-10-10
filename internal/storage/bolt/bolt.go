// Package bolt stores the storage contract's keys and values in one bbolt file.
package bolt

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/dimitrijegasic/seal-gate/internal/storage"
	"go.etcd.io/bbolt"
	berrors "go.etcd.io/bbolt/errors"
)

// ErrLocked is returned by Open when another handle holds the file.
var ErrLocked = errors.New("bolt: database is locked")

// bucket is the one bucket every key lives in.
var bucket = []byte("seal-gate")

// lockTimeout is how long Open waits for the file lock before returning ErrLocked.
const lockTimeout = time.Second

// Backend is a storage.Backend over one bbolt file.
type Backend struct {
	db *bbolt.DB
}

var _ storage.Backend = (*Backend)(nil)

// Open opens or creates the file at path and holds its lock until Close;
// it returns ErrLocked if another handle holds it.
func Open(path string) (*Backend, error) {
	db, err := bbolt.Open(path, 0o600, &bbolt.Options{Timeout: lockTimeout})
	if errors.Is(err, berrors.ErrTimeout) {
		return nil, ErrLocked
	}
	if err != nil {
		return nil, fmt.Errorf("bolt: %w", err)
	}

	err = db.Update(func(tx *bbolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(bucket)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("bolt: %w", errors.Join(err, db.Close()))
	}
	return &Backend{db: db}, nil
}

func (b *Backend) Name() string {
	return "bolt"
}

func (b *Backend) Get(ctx context.Context, key string) ([]byte, error) {
	var value []byte
	err := b.db.View(func(tx *bbolt.Tx) error {
		raw := tx.Bucket(bucket).Get([]byte(key))
		if raw == nil {
			return storage.ErrNotFound
		}
		value = bytes.Clone(raw)
		return nil
	})
	if errors.Is(err, storage.ErrNotFound) {
		return nil, storage.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("bolt: %w", err)
	}
	return value, nil
}

func (b *Backend) Put(ctx context.Context, key string, value []byte) error {
	err := b.db.Update(func(tx *bbolt.Tx) error {
		return tx.Bucket(bucket).Put([]byte(key), value)
	})
	if err != nil {
		return fmt.Errorf("bolt: %w", err)
	}
	return nil
}

func (b *Backend) Delete(ctx context.Context, key string) error {
	err := b.db.Update(func(tx *bbolt.Tx) error {
		return tx.Bucket(bucket).Delete([]byte(key))
	})
	if err != nil {
		return fmt.Errorf("bolt: %w", err)
	}
	return nil
}

func (b *Backend) List(ctx context.Context, prefix string) ([]string, error) {
	var keys []string
	err := b.db.View(func(tx *bbolt.Tx) error {
		c := tx.Bucket(bucket).Cursor()
		p := []byte(prefix)

		// HasPrefix(nil, "") is true; nil ends the bucket.
		for k, _ := c.Seek(p); k != nil && bytes.HasPrefix(k, p); k, _ = c.Next() {
			keys = append(keys, string(k))
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("bolt: %w", err)
	}
	return keys, nil
}

func (b *Backend) Close() error {
	if err := b.db.Close(); err != nil {
		return fmt.Errorf("bolt: %w", err)
	}
	return nil
}
