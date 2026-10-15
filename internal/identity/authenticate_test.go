package identity_test

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"reflect"
	"testing"

	"github.com/dimitrijegasic/seal-gate/internal/authorization"
	"github.com/dimitrijegasic/seal-gate/internal/identity"
)

// Not nil, so a nil token is never root.
var rootToken = bytes.Repeat([]byte{7}, 32)

type fakeRoot struct{}

func (fakeRoot) IsRoot(token []byte) bool {
	return bytes.Equal(token, rootToken)
}

func newAuthenticator(t *testing.T) (*identity.Authenticator, *fakeEntities, *fakeTokens, *fakeGroups) {
	t.Helper()
	entities := &fakeEntities{entities: make(map[string]identity.Entity)}
	tokens := newFakeTokens()
	groups := &fakeGroups{groups: make(map[string]identity.Group)}
	random := &fakeRandom{}
	a := identity.NewAuthenticator(
		fakeRoot{},
		identity.NewTokenService(tokens, identity.NewEntityService(entities, random, &fakeAuthorizer{}), random, &fakeAuthorizer{}, newFakeClock(), tokenLimits),
		identity.NewGroupService(groups, random, &fakeAuthorizer{}),
	)
	return a, entities, tokens, groups
}

func TestAuthenticate(t *testing.T) {
	t.Run("the root token authenticates as the root", func(t *testing.T) {
		a, _, _, _ := newAuthenticator(t)

		got, err := a.Authenticate(t.Context(), rootToken)
		if err != nil {
			t.Fatalf("Authenticate: %v", err)
		}

		if want := authorization.NewRootPrincipal(); !reflect.DeepEqual(got, want) {
			t.Errorf("got %+v, want %+v", got, want)
		}
	})

	t.Run("an entity's token authenticates with its own and its groups' policies", func(t *testing.T) {
		a, entities, tokens, groups := newAuthenticator(t)
		token := bytes.Repeat([]byte{1}, 32)
		tokens.tokens[sha256.Sum256(token)] = liveToken(hexID)
		entities.entities[hexID] = identity.Entity{ID: hexID, Policies: []string{"dev"}, Groups: []string{groupID}}
		groups.groups[groupID] = identity.Group{ID: groupID, Policies: []string{"ops"}}

		got, err := a.Authenticate(t.Context(), token)
		if err != nil {
			t.Fatalf("Authenticate: %v", err)
		}

		if want := authorization.NewEntityPrincipal(hexID, "dev", "ops"); !reflect.DeepEqual(got, want) {
			t.Errorf("got %+v, want %+v", got, want)
		}
	})

	t.Run("an entity's token authenticates to a principal named by the entity", func(t *testing.T) {
		a, entities, tokens, _ := newAuthenticator(t)
		token := bytes.Repeat([]byte{1}, 32)
		tokens.tokens[sha256.Sum256(token)] = liveToken(hexID)
		entities.entities[hexID] = identity.Entity{ID: hexID}

		got, err := a.Authenticate(t.Context(), token)
		if err != nil {
			t.Fatalf("Authenticate: %v", err)
		}

		if got := got.Identity(); got != hexID {
			t.Errorf("got %q, want %q", got, hexID)
		}
	})

	t.Run("the root token is accepted without a token read", func(t *testing.T) {
		a, _, tokens, _ := newAuthenticator(t)
		tokens.err = errDisk

		got, err := a.Authenticate(t.Context(), rootToken)
		if err != nil {
			t.Fatalf("Authenticate: %v", err)
		}

		if want := authorization.NewRootPrincipal(); !reflect.DeepEqual(got, want) {
			t.Errorf("principal: got %+v, want %+v", got, want)
		}
		if tokens.calls != 0 {
			t.Errorf("calls: got %d, want 0", tokens.calls)
		}
	})

	t.Run("a failed token lookup reaches the caller", func(t *testing.T) {
		tests := []struct {
			name    string
			repoErr error
			want    error
		}{
			{"unknown", nil, identity.ErrInvalidToken},
			{"sealed", identity.ErrSealed, identity.ErrSealed},
			{"unexpected", errDisk, errDisk},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				a, _, tokens, _ := newAuthenticator(t)
				tokens.err = tt.repoErr

				_, err := a.Authenticate(t.Context(), bytes.Repeat([]byte{1}, 32))

				if !errors.Is(err, tt.want) {
					t.Errorf("got %v, want %v", err, tt.want)
				}
			})
		}
	})

	t.Run("an unreadable group is an error, not a narrower principal", func(t *testing.T) {
		a, entities, tokens, groups := newAuthenticator(t)
		token := bytes.Repeat([]byte{1}, 32)
		tokens.tokens[sha256.Sum256(token)] = liveToken(hexID)
		entities.entities[hexID] = identity.Entity{ID: hexID, Policies: []string{"dev"}, Groups: []string{groupID}}
		// Dropping the group instead could drop a deny and widen access.
		groups.groups[groupID] = identity.Group{ID: groupID, Policies: []string{"dev/ops"}}

		_, err := a.Authenticate(t.Context(), token)

		if !errors.Is(err, identity.ErrUnreadableGroup) {
			t.Errorf("got %v, want %v", err, identity.ErrUnreadableGroup)
		}
	})
}

var errDisk = errors.New("disk failed")
