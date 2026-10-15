// Package postgres stores the storage contract's keys and values in one Postgres table.
package postgres

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/dimitrijegasic/seal-gate/internal/storage"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrInvalidURL = errors.New("postgres: invalid connection URL")
	ErrConnect    = errors.New("postgres: cannot connect or create the table")
)

// Backend is a storage.Backend over one Postgres table.
type Backend struct {
	pool *pgxpool.Pool
}

var _ storage.Backend = (*Backend)(nil)

// Open connects to the server at connString and creates the table if it is missing.
func Open(ctx context.Context, connString string) (*Backend, error) {
	// pgx's errors are dropped here: its redaction misses malformed URLs, which then leak the password.
	pool, err := pgxpool.New(ctx, connString)
	if err != nil {
		return nil, ErrInvalidURL
	}

	_, err = pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS seal_gate (key bytea PRIMARY KEY, value bytea NOT NULL)`)
	if err != nil {
		pool.Close()
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, fmt.Errorf("postgres: %w", ctxErr)
		}
		return nil, ErrConnect
	}
	return &Backend{pool: pool}, nil
}

func (b *Backend) Name() string {
	return "postgres"
}

func (b *Backend) Get(ctx context.Context, key string) ([]byte, error) {
	var value []byte
	err := b.pool.QueryRow(ctx, `SELECT value FROM seal_gate WHERE key = $1`, []byte(key)).Scan(&value)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, storage.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("postgres: %w", err)
	}
	return value, nil
}

func (b *Backend) Put(ctx context.Context, key string, value []byte) error {
	// pgx sends a nil slice as NULL, which the column refuses.
	if value == nil {
		value = []byte{}
	}

	_, err := b.pool.Exec(ctx,
		`INSERT INTO seal_gate (key, value) VALUES ($1, $2)
		 ON CONFLICT (key) DO UPDATE SET value = excluded.value`,
		[]byte(key), value)
	if err != nil {
		return fmt.Errorf("postgres: %w", err)
	}
	return nil
}

func (b *Backend) Delete(ctx context.Context, key string) error {
	_, err := b.pool.Exec(ctx, `DELETE FROM seal_gate WHERE key = $1`, []byte(key))
	if err != nil {
		return fmt.Errorf("postgres: %w", err)
	}
	return nil
}

func (b *Backend) List(ctx context.Context, prefix string) ([]string, error) {
	query := `SELECT key FROM seal_gate WHERE key >= $1 ORDER BY key`
	args := []any{[]byte(prefix)}
	if end := successor([]byte(prefix)); end != nil {
		query = `SELECT key FROM seal_gate WHERE key >= $1 AND key < $2 ORDER BY key`
		args = append(args, end)
	}

	rows, err := b.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("postgres: %w", err)
	}

	keys, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (string, error) {
		var key []byte
		err := row.Scan(&key)
		return string(key), err
	})
	if err != nil {
		return nil, fmt.Errorf("postgres: %w", err)
	}
	return keys, nil
}

// successor returns the first byte string after every key starting with prefix, or nil when no such bound exists.
func successor(prefix []byte) []byte {
	// A trailing 0xff cannot be incremented, so it is dropped and the byte before it carries.
	// Not bytes.TrimRight: it trims runes, so "\xff" would also match any invalid byte and U+FFFD.
	end := prefix
	for len(end) > 0 && end[len(end)-1] == 0xff {
		end = end[:len(end)-1]
	}
	if len(end) == 0 {
		return nil
	}
	end = bytes.Clone(end)
	end[len(end)-1]++
	return end
}

// Close closes the pool; calling it again is harmless.
func (b *Backend) Close() error {
	b.pool.Close()
	return nil
}
