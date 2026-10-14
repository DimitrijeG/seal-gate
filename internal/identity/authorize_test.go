package identity_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"reflect"
	"testing"

	"github.com/dimitrijegasic/seal-gate/internal/authorization"
	"github.com/dimitrijegasic/seal-gate/internal/identity"
)

// fakeAuthorizer records the last decision asked for; it allows unless err is set.
type fakeAuthorizer struct {
	principal  authorization.Principal
	resource   string
	capability authorization.Capability
	calls      int
	err        error
}

func (a *fakeAuthorizer) Authorize(_ context.Context, principal authorization.Principal, resource string, capability authorization.Capability) error {
	a.calls++
	a.principal = principal
	a.resource = resource
	a.capability = capability
	return a.err
}

func TestAuthorization(t *testing.T) {
	t.Run("a denied get never reaches the repository", func(t *testing.T) {
		s, entities, _, authorizer := newAuthorizedEntityService(t)
		entities.entities[hexID] = identity.Entity{ID: hexID}
		authorizer.err = authorization.ErrDenied

		_, err := s.GetEntity(t.Context(), principal, hexID)

		if !errors.Is(err, authorization.ErrDenied) {
			t.Errorf("err: got %v, want %v", err, authorization.ErrDenied)
		}
		if entities.calls != 0 {
			t.Errorf("calls: got %d, want 0", entities.calls)
		}
	})

	t.Run("each entity operation asks its capability on its resource", func(t *testing.T) {
		tests := []struct {
			name           string
			call           func(ctx context.Context, s *identity.EntityService) error
			wantResource   string
			wantCapability authorization.Capability
		}{
			{"get", func(ctx context.Context, s *identity.EntityService) error {
				_, err := s.GetEntity(ctx, principal, hexID)
				return err
			}, "system/entities/" + hexID, authorization.CapabilityRead},
			{"create", func(ctx context.Context, s *identity.EntityService) error {
				_, err := s.CreateEntity(ctx, principal, identity.Entity{})
				return err
			}, "system/entities", authorization.CapabilityCreate},
			{"delete", func(ctx context.Context, s *identity.EntityService) error {
				return s.DeleteEntity(ctx, principal, hexID)
			}, "system/entities/" + hexID, authorization.CapabilityDelete},
			{"update", func(ctx context.Context, s *identity.EntityService) error {
				return s.UpdateEntity(ctx, principal, identity.Entity{ID: hexID})
			}, "system/entities/" + hexID, authorization.CapabilityUpdate},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				s, entities, _, authorizer := newAuthorizedEntityService(t)
				entities.entities[hexID] = identity.Entity{ID: hexID}

				_ = tt.call(t.Context(), s)

				if authorizer.resource != tt.wantResource {
					t.Errorf("resource: got %q, want %q", authorizer.resource, tt.wantResource)
				}
				if authorizer.capability != tt.wantCapability {
					t.Errorf("capability: got %q, want %q", authorizer.capability, tt.wantCapability)
				}
			})
		}
	})

	t.Run("the principal reaches the authorizer", func(t *testing.T) {
		for _, op := range operations {
			t.Run(op.name, func(t *testing.T) {
				s, entities, _, authorizer := newAuthorizedEntityService(t)
				entities.entities[hexID] = identity.Entity{ID: hexID}

				_ = op.call(t.Context(), s)

				if !reflect.DeepEqual(authorizer.principal, principal) {
					t.Errorf("got %+v, want %+v", authorizer.principal, principal)
				}
			})
		}
	})

	t.Run("a denied operation never reaches the repository", func(t *testing.T) {
		for _, op := range operations {
			t.Run(op.name, func(t *testing.T) {
				s, entities, _, authorizer := newAuthorizedEntityService(t)
				entities.entities[hexID] = identity.Entity{ID: hexID}
				authorizer.err = authorization.ErrDenied

				err := op.call(t.Context(), s)

				if !errors.Is(err, authorization.ErrDenied) {
					t.Errorf("err: got %v, want %v", err, authorization.ErrDenied)
				}
				if entities.calls != 0 {
					t.Errorf("calls: got %d, want 0", entities.calls)
				}
			})
		}
	})

	t.Run("token issue asks create on the entity's tokens resource", func(t *testing.T) {
		s, entities, _, _, authorizer := newAuthorizedTokenService(t)
		entities.entities[hexID] = identity.Entity{ID: hexID}

		_, _ = s.CreateToken(t.Context(), principal, hexID)

		if want := "system/entities/" + hexID + "/tokens"; authorizer.resource != want {
			t.Errorf("resource: got %q, want %q", authorizer.resource, want)
		}
		if authorizer.capability != authorization.CapabilityCreate {
			t.Errorf("capability: got %q, want %q", authorizer.capability, authorization.CapabilityCreate)
		}
	})

	t.Run("a denied token issue reads and stores nothing", func(t *testing.T) {
		s, entities, tokens, _, authorizer := newAuthorizedTokenService(t)
		entities.entities[hexID] = identity.Entity{ID: hexID}
		authorizer.err = authorization.ErrDenied

		_, err := s.CreateToken(t.Context(), principal, hexID)

		if !errors.Is(err, authorization.ErrDenied) {
			t.Errorf("err: got %v, want %v", err, authorization.ErrDenied)
		}
		if entities.calls != 0 {
			t.Errorf("entity calls: got %d, want 0", entities.calls)
		}
		if tokens.calls != 0 {
			t.Errorf("token calls: got %d, want 0", tokens.calls)
		}
	})

	t.Run("resolve finds an entity whatever the authorizer says", func(t *testing.T) {
		s, entities, tokens, _, authorizer := newAuthorizedTokenService(t)
		want := identity.Entity{ID: hexID}
		entities.entities[hexID] = want
		token := bytes.Repeat([]byte{1}, 32)
		tokens.tokens[sha256.Sum256(token)] = hexID
		// Resolve runs before any principal exists, so no decision may stand in its way.
		authorizer.err = authorization.ErrDenied

		got, err := s.Resolve(t.Context(), token)
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}

		if !reflect.DeepEqual(got, want) {
			t.Errorf("got %+v, want %+v", got, want)
		}
	})

	t.Run("a denied group get never reaches the repository", func(t *testing.T) {
		s, groups, _, authorizer := newAuthorizedGroupService(t)
		groups.groups[hexID] = identity.Group{ID: hexID}
		authorizer.err = authorization.ErrDenied

		_, err := s.GetGroup(t.Context(), principal, hexID)

		if !errors.Is(err, authorization.ErrDenied) {
			t.Errorf("err: got %v, want %v", err, authorization.ErrDenied)
		}
		if groups.calls != 0 {
			t.Errorf("calls: got %d, want 0", groups.calls)
		}
	})

	t.Run("each group operation asks its capability on its resource", func(t *testing.T) {
		tests := []struct {
			name           string
			call           func(ctx context.Context, s *identity.GroupService) error
			wantResource   string
			wantCapability authorization.Capability
		}{
			{"get", func(ctx context.Context, s *identity.GroupService) error {
				_, err := s.GetGroup(ctx, principal, hexID)
				return err
			}, "system/groups/" + hexID, authorization.CapabilityRead},
			{"create", func(ctx context.Context, s *identity.GroupService) error {
				_, err := s.CreateGroup(ctx, principal, identity.Group{})
				return err
			}, "system/groups", authorization.CapabilityCreate},
			{"delete", func(ctx context.Context, s *identity.GroupService) error {
				return s.DeleteGroup(ctx, principal, hexID)
			}, "system/groups/" + hexID, authorization.CapabilityDelete},
			{"update", func(ctx context.Context, s *identity.GroupService) error {
				return s.UpdateGroup(ctx, principal, identity.Group{ID: hexID})
			}, "system/groups/" + hexID, authorization.CapabilityUpdate},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				s, groups, _, authorizer := newAuthorizedGroupService(t)
				groups.groups[hexID] = identity.Group{ID: hexID}

				_ = tt.call(t.Context(), s)

				if authorizer.resource != tt.wantResource {
					t.Errorf("resource: got %q, want %q", authorizer.resource, tt.wantResource)
				}
				if authorizer.capability != tt.wantCapability {
					t.Errorf("capability: got %q, want %q", authorizer.capability, tt.wantCapability)
				}
			})
		}
	})

	t.Run("the principal reaches the group authorizer", func(t *testing.T) {
		for _, op := range groupOperations {
			t.Run(op.name, func(t *testing.T) {
				s, groups, _, authorizer := newAuthorizedGroupService(t)
				groups.groups[hexID] = identity.Group{ID: hexID}

				_ = op.call(t.Context(), s)

				if !reflect.DeepEqual(authorizer.principal, principal) {
					t.Errorf("got %+v, want %+v", authorizer.principal, principal)
				}
			})
		}
	})

	t.Run("a denied group operation never reaches the repository", func(t *testing.T) {
		for _, op := range groupOperations {
			t.Run(op.name, func(t *testing.T) {
				s, groups, _, authorizer := newAuthorizedGroupService(t)
				groups.groups[hexID] = identity.Group{ID: hexID}
				authorizer.err = authorization.ErrDenied

				err := op.call(t.Context(), s)

				if !errors.Is(err, authorization.ErrDenied) {
					t.Errorf("err: got %v, want %v", err, authorization.ErrDenied)
				}
				if groups.calls != 0 {
					t.Errorf("calls: got %d, want 0", groups.calls)
				}
			})
		}
	})

	t.Run("effective policies read a group whatever the authorizer says", func(t *testing.T) {
		s, groups, _, authorizer := newAuthorizedGroupService(t)
		groups.groups[hexID] = identity.Group{ID: hexID, Policies: []string{"ops"}}
		entity := identity.Entity{Groups: []string{hexID}}
		want := []string{"ops"}
		// EffectivePolicies runs during authentication, before any principal exists.
		authorizer.err = authorization.ErrDenied

		got, err := s.EffectivePolicies(t.Context(), entity)
		if err != nil {
			t.Fatalf("EffectivePolicies: %v", err)
		}

		if !reflect.DeepEqual(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("an invalid group ID is refused before authorizing", func(t *testing.T) {
		tests := []struct {
			name string
			call func(ctx context.Context, s *identity.GroupService) error
		}{
			{"get", func(ctx context.Context, s *identity.GroupService) error {
				_, err := s.GetGroup(ctx, principal, "../dev")
				return err
			}},
			{"update", func(ctx context.Context, s *identity.GroupService) error {
				return s.UpdateGroup(ctx, principal, identity.Group{ID: "../dev"})
			}},
			{"delete", func(ctx context.Context, s *identity.GroupService) error {
				return s.DeleteGroup(ctx, principal, "../dev")
			}},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				s, _, _, authorizer := newAuthorizedGroupService(t)
				authorizer.err = authorization.ErrDenied

				err := tt.call(t.Context(), s)

				if !errors.Is(err, identity.ErrInvalidGroupID) {
					t.Errorf("got %v, want %v", err, identity.ErrInvalidGroupID)
				}
			})
		}
	})

	t.Run("an invalid ID is refused before authorizing", func(t *testing.T) {
		tests := []struct {
			name string
			call func(ctx context.Context, entities *identity.EntityService, tokens *identity.TokenService) error
		}{
			{"issue token", func(ctx context.Context, _ *identity.EntityService, tokens *identity.TokenService) error {
				_, err := tokens.CreateToken(ctx, principal, "../dev")
				return err
			}},
			{"get", func(ctx context.Context, entities *identity.EntityService, _ *identity.TokenService) error {
				_, err := entities.GetEntity(ctx, principal, "../dev")
				return err
			}},
			{"update", func(ctx context.Context, entities *identity.EntityService, _ *identity.TokenService) error {
				return entities.UpdateEntity(ctx, principal, identity.Entity{ID: "../dev"})
			}},
			{"delete", func(ctx context.Context, entities *identity.EntityService, _ *identity.TokenService) error {
				return entities.DeleteEntity(ctx, principal, "../dev")
			}},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				entities, _, _, authorizer := newAuthorizedEntityService(t)
				tokens := identity.NewTokenService(&fakeTokens{}, entities, &fakeRandom{}, authorizer)
				authorizer.err = authorization.ErrDenied

				err := tt.call(t.Context(), entities, tokens)

				if !errors.Is(err, identity.ErrInvalidEntityID) {
					t.Errorf("got %v, want %v", err, identity.ErrInvalidEntityID)
				}
			})
		}
	})
}
