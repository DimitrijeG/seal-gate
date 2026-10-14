package app

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"

	"github.com/dimitrijegasic/seal-gate/internal/authorization"
	"github.com/dimitrijegasic/seal-gate/internal/barrier"
	"github.com/dimitrijegasic/seal-gate/internal/config"
	"github.com/dimitrijegasic/seal-gate/internal/cryptography"
	"github.com/dimitrijegasic/seal-gate/internal/httpapi"
	"github.com/dimitrijegasic/seal-gate/internal/identity"
	"github.com/dimitrijegasic/seal-gate/internal/repository"
	"github.com/dimitrijegasic/seal-gate/internal/secret"
	"github.com/dimitrijegasic/seal-gate/internal/storage"
	"github.com/dimitrijegasic/seal-gate/internal/system"
)

type infrastructure struct {
	logger  *slog.Logger
	clock   system.Clock
	keys    *cryptography.KeyHolder
	cipher  cryptography.Cipher
	shamir  *cryptography.Shamir
	wrapper *cryptography.KeyWrapper
	random  cryptography.CryptoRandom
}

type repositories struct {
	set *repository.Set
}

type services struct {
	authenticator *identity.Authenticator
	system        *system.Service
	secret        *secret.Service
	policy        *authorization.Service
	entity        *identity.EntityService
	token         *identity.TokenService
	group         *identity.GroupService
}

func buildInfrastructure(cfg *config.Config) (*infrastructure, error) {
	var level slog.Level
	if err := level.UnmarshalText([]byte(cfg.Logger.Level)); err != nil {
		return nil, fmt.Errorf("app: logger level: %w", err)
	}

	options := &slog.HandlerOptions{Level: level}
	var handler slog.Handler = slog.NewJSONHandler(os.Stdout, options)
	if cfg.Logger.Format == "text" {
		handler = slog.NewTextHandler(os.Stdout, options)
	}

	cipher, err := cryptography.NewAEADCipher(cfg.Crypto.AEADAlgorithm)
	if err != nil {
		return nil, fmt.Errorf("app: cipher: %w", err)
	}

	random := cryptography.CryptoRandom{}
	shamir := cryptography.NewShamir(random)

	return &infrastructure{
		logger:  slog.New(handler),
		clock:   systemClock{},
		keys:    cryptography.NewKeyHolder(),
		cipher:  cipher,
		shamir:  shamir,
		wrapper: cryptography.NewKeyWrapper(cipher),
		random:  random,
	}, nil
}

func buildRepositories(backend storage.Backend, infra *infrastructure) *repositories {
	encrypted := barrier.NewAEADBarrier(backend, infra.keys, infra.cipher)
	return &repositories{
		set: repository.NewSet(backend, encrypted),
	}
}

func buildServices(infra *infrastructure, repositories *repositories) *services {
	keyring := system.NewKeyring(
		repositories.set.System,
		infra.shamir,
		infra.wrapper,
		infra.random,
		infra.keys,
	)

	sys := system.NewService(keyring, infra.clock)
	entity := identity.NewEntityService(repositories.set.Entity, infra.random)
	token := identity.NewTokenService(repositories.set.Token, entity, infra.random)
	group := identity.NewGroupService(repositories.set.Group, infra.random)

	return &services{
		authenticator: identity.NewAuthenticator(sys, token, group),
		system:        sys,
		secret:        secret.New(repositories.set.Secret),
		policy:        authorization.New(repositories.set.Policy),
		entity:        entity,
		token:         token,
		group:         group,
	}
}

func buildRouter(services *services, logger *slog.Logger) http.Handler {
	return httpapi.NewRouter(&httpapi.Handlers{
		Authenticator: services.authenticator,
		System:        services.system,
		Secret:        services.secret,
		Policy:        services.policy,
		Entity:        services.entity,
		Token:         services.token,
		Group:         services.group,
		Logger:        logger,
	})
}

func buildHTTP(cfg *config.Config, services *services, logger *slog.Logger) *httpapi.Server {
	return httpapi.NewServer(cfg, buildRouter(services, logger), logger)
}
