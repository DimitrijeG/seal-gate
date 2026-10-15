package app

import (
	"context"

	"github.com/dimitrijegasic/seal-gate/internal/identity"
	"github.com/dimitrijegasic/seal-gate/internal/lifecycle"
	"github.com/dimitrijegasic/seal-gate/internal/secret"
)

// secretResource turns a secret path into the resource name policies and the audit trail use for it.
const secretResource = "secrets/"

// secretOperations names each sweep action as the audit trail's route.
var secretOperations = map[secret.ActionKind]string{
	secret.ActionRotated: "rotate secret",
	secret.ActionExpired: "expire secret",
}

// secretSweep runs the secret service's sweep as a lifecycle job.
type secretSweep struct{ secrets *secret.Service }

var _ lifecycle.Job = secretSweep{}

func (j secretSweep) Run(ctx context.Context, report func(lifecycle.Action)) error {
	return j.secrets.Sweep(ctx, func(action secret.Action) {
		report(lifecycle.Action{Operation: secretOperations[action.Kind], Resource: secretResource + action.Path})
	})
}

// tokenPurge runs the token service's purge of expired tokens as a lifecycle job.
type tokenPurge struct{ tokens *identity.TokenService }

var _ lifecycle.Job = tokenPurge{}

func (j tokenPurge) Run(ctx context.Context, report func(lifecycle.Action)) error {
	// No resource: a token's hash is its only name, and it must not reach the audit trail.
	return j.tokens.PurgeExpired(ctx, func() { report(lifecycle.Action{Operation: "expire token"}) })
}
