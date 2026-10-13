package identity_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/dimitrijegasic/seal-gate/internal/identity"
)

// fakeTokens keeps entity IDs by token hash; err, when set, fails every call.
type fakeTokens struct {
	tokens map[[sha256.Size]byte]string
	calls  int
	err    error
}

func (r *fakeTokens) Put(_ context.Context, hash [sha256.Size]byte, entityID string) error {
	r.calls++
	if r.err != nil {
		return r.err
	}
	r.tokens[hash] = entityID
	return nil
}

func (r *fakeTokens) Get(_ context.Context, hash [sha256.Size]byte) (string, error) {
	r.calls++
	if r.err != nil {
		return "", r.err
	}
	entityID, ok := r.tokens[hash]
	if !ok {
		return "", identity.ErrInvalidToken
	}
	return entityID, nil
}

func newTokenService(t *testing.T) (*identity.Service, *fakeEntities, *fakeTokens, *fakeRandom) {
	t.Helper()
	entities := &fakeEntities{entities: make(map[string]identity.Entity)}
	tokens := &fakeTokens{tokens: make(map[[sha256.Size]byte]string)}
	random := &fakeRandom{}
	groups := &fakeGroups{groups: make(map[string]identity.Group)}
	return identity.New(entities, tokens, groups, random), entities, tokens, random
}

func TestToken(t *testing.T) {
	t.Run("a created token resolves to its entity", func(t *testing.T) {
		s, entities, _, _ := newTokenService(t)
		entity := identity.Entity{ID: hexID, Policies: []string{"dev"}}
		entities.entities[hexID] = entity

		token, err := s.CreateToken(t.Context(), hexID)
		if err != nil {
			t.Fatalf("CreateToken: %v", err)
		}
		got, err := s.Resolve(t.Context(), token)
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}

		if !reflect.DeepEqual(got, entity) {
			t.Errorf("got %+v, want %+v", got, entity)
		}
	})

	t.Run("a token is 32 bytes from the random source", func(t *testing.T) {
		s, entities, _, _ := newTokenService(t)
		entities.entities[hexID] = identity.Entity{ID: hexID}

		token, err := s.CreateToken(t.Context(), hexID)
		if err != nil {
			t.Fatalf("CreateToken: %v", err)
		}

		// fakeRandom's first call fills every byte with 1.
		if want := bytes.Repeat([]byte{1}, 32); !bytes.Equal(token, want) {
			t.Errorf("got %x, want %x", token, want)
		}
	})

	t.Run("only the token's hash is stored", func(t *testing.T) {
		s, entities, tokens, _ := newTokenService(t)
		entities.entities[hexID] = identity.Entity{ID: hexID}

		token, err := s.CreateToken(t.Context(), hexID)
		if err != nil {
			t.Fatalf("CreateToken: %v", err)
		}

		want := map[[sha256.Size]byte]string{sha256.Sum256(token): hexID}
		if !reflect.DeepEqual(tokens.tokens, want) {
			t.Errorf("got %x, want %x", tokens.tokens, want)
		}
	})

	t.Run("a token for a missing entity is not found", func(t *testing.T) {
		s, _, tokens, _ := newTokenService(t)

		_, err := s.CreateToken(t.Context(), hexID)

		if !errors.Is(err, identity.ErrEntityNotFound) {
			t.Errorf("err: got %v, want %v", err, identity.ErrEntityNotFound)
		}
		if tokens.calls != 0 {
			t.Errorf("calls: got %d, want 0", tokens.calls)
		}
	})

	t.Run("a token for an invalid entity ID is refused before any read", func(t *testing.T) {
		s, entities, tokens, _ := newTokenService(t)

		_, err := s.CreateToken(t.Context(), "../dev")

		if !errors.Is(err, identity.ErrInvalidEntityID) {
			t.Errorf("err: got %v, want %v", err, identity.ErrInvalidEntityID)
		}
		if entities.calls != 0 {
			t.Errorf("entity calls: got %d, want 0", entities.calls)
		}
		if tokens.calls != 0 {
			t.Errorf("token calls: got %d, want 0", tokens.calls)
		}
	})

	t.Run("an unknown token is refused", func(t *testing.T) {
		s, _, _, _ := newTokenService(t)

		_, err := s.Resolve(t.Context(), bytes.Repeat([]byte{9}, 32))

		if !errors.Is(err, identity.ErrInvalidToken) {
			t.Errorf("got %v, want %v", err, identity.ErrInvalidToken)
		}
	})

	t.Run("a missing token is refused like an unknown one without a read", func(t *testing.T) {
		tests := []struct {
			name  string
			token []byte
		}{
			{"nil", nil},
			{"empty", []byte{}},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				s, _, tokens, _ := newTokenService(t)

				_, err := s.Resolve(t.Context(), tt.token)

				if !errors.Is(err, identity.ErrInvalidToken) {
					t.Errorf("err: got %v, want %v", err, identity.ErrInvalidToken)
				}
				if tokens.calls != 0 {
					t.Errorf("calls: got %d, want 0", tokens.calls)
				}
			})
		}
	})

	t.Run("a token of the wrong length is refused without a read", func(t *testing.T) {
		tests := []struct {
			name  string
			token []byte
		}{
			{"31 bytes", bytes.Repeat([]byte{1}, 31)},
			{"33 bytes", bytes.Repeat([]byte{1}, 33)},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				s, _, tokens, _ := newTokenService(t)

				_, err := s.Resolve(t.Context(), tt.token)

				if !errors.Is(err, identity.ErrInvalidToken) {
					t.Errorf("err: got %v, want %v", err, identity.ErrInvalidToken)
				}
				if tokens.calls != 0 {
					t.Errorf("calls: got %d, want 0", tokens.calls)
				}
			})
		}
	})

	t.Run("a token whose entity was deleted is refused like an unknown one", func(t *testing.T) {
		s, entities, _, _ := newTokenService(t)
		entities.entities[hexID] = identity.Entity{ID: hexID}
		token, err := s.CreateToken(t.Context(), hexID)
		if err != nil {
			t.Fatalf("CreateToken: %v", err)
		}
		if err := s.DeleteEntity(t.Context(), hexID); err != nil {
			t.Fatalf("DeleteEntity: %v", err)
		}

		_, err = s.Resolve(t.Context(), token)

		if !errors.Is(err, identity.ErrInvalidToken) {
			t.Errorf("got %v, want %v", err, identity.ErrInvalidToken)
		}
	})

	t.Run("a token whose entity is unreadable reports unreadable", func(t *testing.T) {
		s, entities, tokens, _ := newTokenService(t)
		token := bytes.Repeat([]byte{1}, 32)
		tokens.tokens[sha256.Sum256(token)] = hexID
		entities.entities[hexID] = identity.Entity{ID: hexID, Policies: []string{"dev/ops"}}

		_, err := s.Resolve(t.Context(), token)

		if !errors.Is(err, identity.ErrUnreadableEntity) {
			t.Errorf("got %v, want %v", err, identity.ErrUnreadableEntity)
		}
	})

	t.Run("a refused token does not appear in the error", func(t *testing.T) {
		s, _, _, _ := newTokenService(t)
		token := []byte("printable-token-never-issued-32b")

		_, err := s.Resolve(t.Context(), token)
		if err == nil {
			t.Fatal("got nil, want an error")
		}

		for _, form := range []string{string(token), hex.EncodeToString(token), base64.StdEncoding.EncodeToString(token)} {
			if strings.Contains(err.Error(), form) {
				t.Errorf("got %q, want no %q", err, form)
			}
		}
	})

	t.Run("a stored token naming an invalid entity ID is unreadable", func(t *testing.T) {
		s, _, tokens, _ := newTokenService(t)
		token := bytes.Repeat([]byte{1}, 32)
		tokens.tokens[sha256.Sum256(token)] = "../dev"

		_, err := s.Resolve(t.Context(), token)

		if !errors.Is(err, identity.ErrUnreadableToken) {
			t.Errorf("got %v, want %v", err, identity.ErrUnreadableToken)
		}
	})

	t.Run("every token operation reports sealed", func(t *testing.T) {
		for _, op := range tokenOperations {
			t.Run(op.name, func(t *testing.T) {
				s, entities, tokens, _ := newTokenService(t)
				entities.entities[hexID] = identity.Entity{ID: hexID}
				tokens.err = identity.ErrSealed

				err := op.call(t.Context(), s)

				if !errors.Is(err, identity.ErrSealed) {
					t.Errorf("got %v, want %v", err, identity.ErrSealed)
				}
			})
		}
	})

	t.Run("an unexpected token repository failure reaches the caller", func(t *testing.T) {
		for _, op := range tokenOperations {
			t.Run(op.name, func(t *testing.T) {
				s, entities, tokens, _ := newTokenService(t)
				entities.entities[hexID] = identity.Entity{ID: hexID}
				repoErr := errors.New("disk failed")
				tokens.err = repoErr

				err := op.call(t.Context(), s)

				if !errors.Is(err, repoErr) {
					t.Errorf("got %v, want %v", err, repoErr)
				}
			})
		}
	})

	t.Run("a token that fails to store is cleared", func(t *testing.T) {
		s, entities, tokens, random := newTokenService(t)
		entities.entities[hexID] = identity.Entity{ID: hexID}
		tokens.err = identity.ErrSealed
		want := make([]byte, 32)

		if _, err := s.CreateToken(t.Context(), hexID); !errors.Is(err, identity.ErrSealed) {
			t.Fatalf("CreateToken: %v", err)
		}

		if !bytes.Equal(random.last, want) {
			t.Errorf("got %x, want %x", random.last, want)
		}
	})

	t.Run("a failed random source stores no token", func(t *testing.T) {
		s, entities, tokens, random := newTokenService(t)
		entities.entities[hexID] = identity.Entity{ID: hexID}
		randomErr := errors.New("entropy exhausted")
		random.err = randomErr

		_, err := s.CreateToken(t.Context(), hexID)

		if !errors.Is(err, randomErr) {
			t.Errorf("err: got %v, want %v", err, randomErr)
		}
		if tokens.calls != 0 {
			t.Errorf("calls: got %d, want 0", tokens.calls)
		}
	})
}

// tokenOperations calls each token method with valid input for an entity stored under hexID,
// so only the token repository can fail it.
var tokenOperations = []struct {
	name string
	call func(ctx context.Context, s *identity.Service) error
}{
	{"create", func(ctx context.Context, s *identity.Service) error {
		_, err := s.CreateToken(ctx, hexID)
		return err
	}},
	{"resolve", func(ctx context.Context, s *identity.Service) error {
		_, err := s.Resolve(ctx, bytes.Repeat([]byte{1}, 32))
		return err
	}},
}
