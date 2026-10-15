package identity_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"maps"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/dimitrijegasic/seal-gate/internal/identity"
)

// fakeTokens keeps stored tokens by hash; err, when set, fails every call.
type fakeTokens struct {
	tokens map[[sha256.Size]byte]identity.StoredToken
	calls  int
	err    error
}

func (r *fakeTokens) Put(_ context.Context, hash [sha256.Size]byte, token identity.StoredToken) error {
	r.calls++
	if r.err != nil {
		return r.err
	}
	r.tokens[hash] = token
	return nil
}

func (r *fakeTokens) Get(_ context.Context, hash [sha256.Size]byte) (identity.StoredToken, error) {
	r.calls++
	if r.err != nil {
		return identity.StoredToken{}, r.err
	}
	token, ok := r.tokens[hash]
	if !ok {
		return identity.StoredToken{}, identity.ErrInvalidToken
	}
	return token, nil
}

func (r *fakeTokens) Delete(_ context.Context, hash [sha256.Size]byte) error {
	r.calls++
	if r.err != nil {
		return r.err
	}
	delete(r.tokens, hash)
	return nil
}

// fakeClock reads as now; tests move it with advance.
type fakeClock struct{ now time.Time }

func (c *fakeClock) Now() time.Time { return c.now }

func (c *fakeClock) advance(d time.Duration) { c.now = c.now.Add(d) }

func newFakeClock() *fakeClock {
	return &fakeClock{now: time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)}
}

// liveToken is a stored token for entityID that has not expired at the fake clock's time.
func liveToken(entityID string) identity.StoredToken {
	return identity.StoredToken{EntityID: entityID, ExpiresAt: newFakeClock().now.Add(tokenTTL)}
}

func newFakeTokens() *fakeTokens {
	return &fakeTokens{tokens: make(map[[sha256.Size]byte]identity.StoredToken)}
}

// tokenTTL is not an hour, so a TTL hard-coded to the config default fails.
const tokenTTL = 90 * time.Minute

var tokenLimits = identity.TokenTTL{Default: tokenTTL, Max: 24 * time.Hour}

// invalidTTLs are the TTLs CreateToken refuses under tokenLimits.
var invalidTTLs = []struct {
	name string
	ttl  time.Duration
}{
	{"negative", -time.Second},
	{"above the maximum", tokenLimits.Max + time.Second},
}

func newTokenService(t *testing.T) (*identity.TokenService, *fakeEntities, *fakeTokens, *fakeRandom) {
	t.Helper()
	s, entities, tokens, random, _ := newAuthorizedTokenService(t)
	return s, entities, tokens, random
}

// newClockedTokenService is newTokenService that also returns the clock the service reads, for the test to move.
func newClockedTokenService(t *testing.T) (*identity.TokenService, *fakeEntities, *fakeTokens, *fakeClock) {
	t.Helper()
	entities := &fakeEntities{entities: make(map[string]identity.Entity)}
	tokens := newFakeTokens()
	random := &fakeRandom{}
	authorizer := &fakeAuthorizer{}
	clock := newFakeClock()
	s := identity.NewTokenService(tokens, identity.NewEntityService(entities, random, authorizer), fakeRoot{}, random, authorizer, clock, tokenLimits)
	return s, entities, tokens, clock
}

// newAuthorizedTokenService gives both services one authorizer, so an entity read the token service authorizes shows in it.
func newAuthorizedTokenService(t *testing.T) (*identity.TokenService, *fakeEntities, *fakeTokens, *fakeRandom, *fakeAuthorizer) {
	t.Helper()
	entities := &fakeEntities{entities: make(map[string]identity.Entity)}
	tokens := newFakeTokens()
	random := &fakeRandom{}
	authorizer := &fakeAuthorizer{}
	s := identity.NewTokenService(tokens, identity.NewEntityService(entities, random, authorizer), fakeRoot{}, random, authorizer, newFakeClock(), tokenLimits)
	return s, entities, tokens, random, authorizer
}

func TestToken(t *testing.T) {
	t.Run("a created token resolves to its entity", func(t *testing.T) {
		s, entities, _, _ := newTokenService(t)
		entity := identity.Entity{ID: hexID, Policies: []string{"dev"}}
		entities.entities[hexID] = entity

		token, _, err := s.CreateToken(t.Context(), principal, hexID, 0)
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

		token, _, err := s.CreateToken(t.Context(), principal, hexID, 0)
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

		token, _, err := s.CreateToken(t.Context(), principal, hexID, 0)
		if err != nil {
			t.Fatalf("CreateToken: %v", err)
		}

		want := [][sha256.Size]byte{sha256.Sum256(token)}
		if got := slices.Collect(maps.Keys(tokens.tokens)); !reflect.DeepEqual(got, want) {
			t.Errorf("got %x, want %x", got, want)
		}
	})

	t.Run("a token without a TTL is stored to expire one default TTL after it is issued", func(t *testing.T) {
		s, entities, tokens, clock := newClockedTokenService(t)
		entities.entities[hexID] = identity.Entity{ID: hexID}
		clock.advance(time.Minute)
		want := clock.now.Add(tokenTTL)

		token, _, err := s.CreateToken(t.Context(), principal, hexID, 0)
		if err != nil {
			t.Fatalf("CreateToken: %v", err)
		}

		if got := tokens.tokens[sha256.Sum256(token)].ExpiresAt; !got.Equal(want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("an issued token's expiry is returned with it", func(t *testing.T) {
		s, entities, _, clock := newClockedTokenService(t)
		entities.entities[hexID] = identity.Entity{ID: hexID}
		want := clock.now.Add(tokenTTL)

		_, got, err := s.CreateToken(t.Context(), principal, hexID, 0)
		if err != nil {
			t.Fatalf("CreateToken: %v", err)
		}

		if !got.Equal(want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("a token issued with a TTL expires after it", func(t *testing.T) {
		s, entities, _, clock := newClockedTokenService(t)
		entities.entities[hexID] = identity.Entity{ID: hexID}
		want := clock.now.Add(2 * time.Hour)

		_, got, err := s.CreateToken(t.Context(), principal, hexID, 2*time.Hour)
		if err != nil {
			t.Fatalf("CreateToken: %v", err)
		}

		if !got.Equal(want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("an invalid TTL is refused", func(t *testing.T) {
		for _, tt := range invalidTTLs {
			t.Run(tt.name, func(t *testing.T) {
				s, entities, _, _ := newTokenService(t)
				entities.entities[hexID] = identity.Entity{ID: hexID}

				_, _, err := s.CreateToken(t.Context(), principal, hexID, tt.ttl)

				if !errors.Is(err, identity.ErrInvalidTTL) {
					t.Errorf("got %v, want %v", err, identity.ErrInvalidTTL)
				}
			})
		}
	})

	t.Run("a TTL at the maximum is accepted", func(t *testing.T) {
		s, entities, _, clock := newClockedTokenService(t)
		entities.entities[hexID] = identity.Entity{ID: hexID}
		want := clock.now.Add(tokenLimits.Max)

		_, got, err := s.CreateToken(t.Context(), principal, hexID, tokenLimits.Max)
		if err != nil {
			t.Fatalf("CreateToken: %v", err)
		}

		if !got.Equal(want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("an invalid TTL is refused before any read", func(t *testing.T) {
		for _, tt := range invalidTTLs {
			t.Run(tt.name, func(t *testing.T) {
				s, entities, tokens, _ := newTokenService(t)

				_, _, _ = s.CreateToken(t.Context(), principal, hexID, tt.ttl)

				if entities.calls != 0 {
					t.Errorf("entity calls: got %d, want 0", entities.calls)
				}
				if tokens.calls != 0 {
					t.Errorf("token calls: got %d, want 0", tokens.calls)
				}
			})
		}
	})

	t.Run("a revoked token no longer resolves", func(t *testing.T) {
		s, entities, _, _ := newTokenService(t)
		entities.entities[hexID] = identity.Entity{ID: hexID}
		token, _, err := s.CreateToken(t.Context(), principal, hexID, 0)
		if err != nil {
			t.Fatalf("CreateToken: %v", err)
		}

		if err := s.RevokeToken(t.Context(), token); err != nil {
			t.Fatalf("RevokeToken: %v", err)
		}
		_, err = s.Resolve(t.Context(), token)

		if !errors.Is(err, identity.ErrInvalidToken) {
			t.Errorf("got %v, want %v", err, identity.ErrInvalidToken)
		}
	})

	t.Run("the root token cannot be revoked", func(t *testing.T) {
		s, _, _, _ := newTokenService(t)

		err := s.RevokeToken(t.Context(), rootToken)

		if !errors.Is(err, identity.ErrRootToken) {
			t.Errorf("got %v, want %v", err, identity.ErrRootToken)
		}
	})

	t.Run("a revoke of a missing or wrong-length token is refused without a write", func(t *testing.T) {
		tests := []struct {
			name  string
			token []byte
		}{
			{"nil", nil},
			{"empty", []byte{}},
			{"31 bytes", bytes.Repeat([]byte{1}, 31)},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				s, _, tokens, _ := newTokenService(t)

				err := s.RevokeToken(t.Context(), tt.token)

				if !errors.Is(err, identity.ErrInvalidToken) {
					t.Errorf("err: got %v, want %v", err, identity.ErrInvalidToken)
				}
				if tokens.calls != 0 {
					t.Errorf("calls: got %d, want 0", tokens.calls)
				}
			})
		}
	})

	t.Run("a token for a missing entity is not found", func(t *testing.T) {
		s, _, tokens, _ := newTokenService(t)

		_, _, err := s.CreateToken(t.Context(), principal, hexID, 0)

		if !errors.Is(err, identity.ErrEntityNotFound) {
			t.Errorf("err: got %v, want %v", err, identity.ErrEntityNotFound)
		}
		if tokens.calls != 0 {
			t.Errorf("calls: got %d, want 0", tokens.calls)
		}
	})

	t.Run("a token for an invalid entity ID is refused before any read", func(t *testing.T) {
		s, entities, tokens, _ := newTokenService(t)

		_, _, err := s.CreateToken(t.Context(), principal, "../dev", 0)

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
		token, _, err := s.CreateToken(t.Context(), principal, hexID, 0)
		if err != nil {
			t.Fatalf("CreateToken: %v", err)
		}
		delete(entities.entities, hexID)

		_, err = s.Resolve(t.Context(), token)

		if !errors.Is(err, identity.ErrInvalidToken) {
			t.Errorf("got %v, want %v", err, identity.ErrInvalidToken)
		}
	})

	t.Run("a token whose entity is unreadable reports unreadable", func(t *testing.T) {
		s, entities, tokens, _ := newTokenService(t)
		token := bytes.Repeat([]byte{1}, 32)
		tokens.tokens[sha256.Sum256(token)] = liveToken(hexID)
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

	t.Run("an expired token is refused like an unknown one", func(t *testing.T) {
		tests := []struct {
			name    string
			elapsed time.Duration
		}{
			{"at its expiry", tokenTTL},
			{"past its expiry", tokenTTL + time.Second},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				s, entities, _, clock := newClockedTokenService(t)
				entities.entities[hexID] = identity.Entity{ID: hexID}
				token, _, err := s.CreateToken(t.Context(), principal, hexID, 0)
				if err != nil {
					t.Fatalf("CreateToken: %v", err)
				}
				clock.advance(tt.elapsed)

				_, err = s.Resolve(t.Context(), token)

				if !errors.Is(err, identity.ErrInvalidToken) {
					t.Errorf("got %v, want %v", err, identity.ErrInvalidToken)
				}
			})
		}
	})

	t.Run("a stored token naming an invalid entity ID is unreadable", func(t *testing.T) {
		s, _, tokens, _ := newTokenService(t)
		token := bytes.Repeat([]byte{1}, 32)
		tokens.tokens[sha256.Sum256(token)] = liveToken("../dev")

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

		if _, _, err := s.CreateToken(t.Context(), principal, hexID, 0); !errors.Is(err, identity.ErrSealed) {
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

		_, _, err := s.CreateToken(t.Context(), principal, hexID, 0)

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
	call func(ctx context.Context, s *identity.TokenService) error
}{
	{"create", func(ctx context.Context, s *identity.TokenService) error {
		_, _, err := s.CreateToken(ctx, principal, hexID, 0)
		return err
	}},
	{"resolve", func(ctx context.Context, s *identity.TokenService) error {
		_, err := s.Resolve(ctx, bytes.Repeat([]byte{1}, 32))
		return err
	}},
	{"revoke", func(ctx context.Context, s *identity.TokenService) error {
		return s.RevokeToken(ctx, bytes.Repeat([]byte{1}, 32))
	}},
}
