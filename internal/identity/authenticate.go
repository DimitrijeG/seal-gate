package identity

import (
	"context"

	"github.com/dimitrijegasic/seal-gate/internal/authorization"
)

// RootChecker recognises the root token without reading storage; it answers false while sealed.
type RootChecker interface {
	IsRoot(token []byte) bool
}

// Authenticator turns a token into the principal it acts as: the root, or an entity's own and groups' policies.
type Authenticator struct {
	root   RootChecker
	tokens *TokenService
	groups *GroupService
}

// NewAuthenticator returns an Authenticator that asks root first, then resolves other tokens through tokens and groups.
func NewAuthenticator(root RootChecker, tokens *TokenService, groups *GroupService) *Authenticator {
	return &Authenticator{root: root, tokens: tokens, groups: groups}
}

// Authenticate returns the principal token acts as; an unknown token is ErrInvalidToken, and an unreadable
// entity or group is an error, never a principal with fewer policies.
func (a *Authenticator) Authenticate(ctx context.Context, token []byte) (authorization.Principal, error) {
	if a.root.IsRoot(token) {
		return authorization.NewRootPrincipal(), nil
	}

	entity, err := a.tokens.Resolve(ctx, token)
	if err != nil {
		return authorization.Principal{}, err
	}

	policies, err := a.groups.EffectivePolicies(ctx, entity)
	if err != nil {
		return authorization.Principal{}, err
	}

	return authorization.NewPolicyPrincipal(policies...), nil
}
