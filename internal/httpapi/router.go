package httpapi

import (
	"context"
	"encoding/base64"
	"log/slog"
	"net/http"
	"path"
	"strings"

	"github.com/dimitrijegasic/seal-gate/internal/authorization"
	"github.com/dimitrijegasic/seal-gate/internal/identity"
	"github.com/dimitrijegasic/seal-gate/internal/secret"
	"github.com/dimitrijegasic/seal-gate/internal/system"
)

// SystemService is the seal lifecycle as the handlers use it.
type SystemService interface {
	Init(ctx context.Context, cfg system.SealConfiguration) (system.InitResult, error)
	Unseal(ctx context.Context, share []byte) (system.Status, error)
	ResetUnseal(ctx context.Context) (system.Status, error)
	Seal(ctx context.Context, principal authorization.Principal) error
	Status(ctx context.Context) (system.Status, error)
}

// SecretService is secret storage as the handlers use it.
type SecretService interface {
	Put(ctx context.Context, principal authorization.Principal, path string, value []byte) error
	Get(ctx context.Context, principal authorization.Principal, path string) ([]byte, error)
	Delete(ctx context.Context, principal authorization.Principal, path string) error
	List(ctx context.Context, principal authorization.Principal, prefix string) ([]string, error)
}

// PolicyService is policy storage as the handlers use it.
type PolicyService interface {
	Put(ctx context.Context, principal authorization.Principal, policy authorization.Policy) error
	Get(ctx context.Context, principal authorization.Principal, name string) (authorization.Policy, error)
	Delete(ctx context.Context, principal authorization.Principal, name string) error
}

// EntityService is entity storage as the handlers use it.
type EntityService interface {
	CreateEntity(ctx context.Context, principal authorization.Principal, entity identity.Entity) (string, error)
	GetEntity(ctx context.Context, principal authorization.Principal, id string) (identity.Entity, error)
	UpdateEntity(ctx context.Context, principal authorization.Principal, entity identity.Entity) error
	DeleteEntity(ctx context.Context, principal authorization.Principal, id string) error
}

// TokenService is token issuing as the handlers use it.
type TokenService interface {
	CreateToken(ctx context.Context, principal authorization.Principal, entityID string) ([]byte, error)
}

// GroupService is group storage as the handlers use it.
type GroupService interface {
	CreateGroup(ctx context.Context, principal authorization.Principal, group identity.Group) (string, error)
	GetGroup(ctx context.Context, principal authorization.Principal, id string) (identity.Group, error)
	UpdateGroup(ctx context.Context, principal authorization.Principal, group identity.Group) error
	DeleteGroup(ctx context.Context, principal authorization.Principal, id string) error
}

// Authenticator turns a request's token into the principal it acts as; an unknown token must be identity.ErrInvalidToken, as anything else is a 500.
type Authenticator interface {
	Authenticate(ctx context.Context, token []byte) (authorization.Principal, error)
}

// Handlers holds what the HTTP handlers call.
type Handlers struct {
	Authenticator Authenticator
	System        SystemService
	Secret        SecretService
	Policy        PolicyService
	Entity        EntityService
	Token         TokenService
	Group         GroupService
	Logger        *slog.Logger
}

func NewRouter(h *Handlers) http.Handler {
	mux := http.NewServeMux()

	// Open: they must work before any token exists, or while none can be checked.
	mux.HandleFunc("POST /v1/sys/init", h.handleInit)
	mux.HandleFunc("POST /v1/sys/unseal", h.handleUnseal)
	mux.HandleFunc("GET /v1/sys/status", h.handleStatus)
	mux.HandleFunc("GET /v1/sys/health", h.handleHealth)

	mux.Handle("POST /v1/sys/seal", h.authenticate(h.handleSeal))

	mux.Handle("GET /v1/secrets", h.authenticate(h.handleListSecrets))
	mux.Handle("PUT /v1/secrets/{path...}", h.authenticate(h.handlePutSecret))
	mux.Handle("GET /v1/secrets/{path...}", h.authenticate(h.handleGetSecret))
	mux.Handle("DELETE /v1/secrets/{path...}", h.authenticate(h.handleDeleteSecret))

	mux.Handle("PUT /v1/policies/{name}", h.authenticate(h.handlePutPolicy))
	mux.Handle("GET /v1/policies/{name}", h.authenticate(h.handleGetPolicy))
	mux.Handle("DELETE /v1/policies/{name}", h.authenticate(h.handleDeletePolicy))

	mux.Handle("POST /v1/entities", h.authenticate(h.handleCreateEntity))
	mux.Handle("GET /v1/entities/{id}", h.authenticate(h.handleGetEntity))
	mux.Handle("PUT /v1/entities/{id}", h.authenticate(h.handleUpdateEntity))
	mux.Handle("DELETE /v1/entities/{id}", h.authenticate(h.handleDeleteEntity))
	mux.Handle("POST /v1/entities/{id}/tokens", h.authenticate(h.handleCreateToken))

	mux.Handle("POST /v1/groups", h.authenticate(h.handleCreateGroup))
	mux.Handle("GET /v1/groups/{id}", h.authenticate(h.handleGetGroup))
	mux.Handle("PUT /v1/groups/{id}", h.authenticate(h.handleUpdateGroup))
	mux.Handle("DELETE /v1/groups/{id}", h.authenticate(h.handleDeleteGroup))

	return h.refuseUncleanPaths(mux)
}

// authenticate refuses a request whose bearer token does not authenticate, before next runs.
func (h *Handlers) authenticate(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The scheme is case-insensitive (RFC 7235); the token is not.
		scheme, encoded, _ := strings.Cut(r.Header.Get("Authorization"), " ")
		if !strings.EqualFold(scheme, "Bearer") {
			writeError(w, h.Logger, errUnauthenticated)
			return
		}
		token, err := base64.StdEncoding.DecodeString(encoded)
		// Deferred before the check: a rejected decode can still return the bytes it read.
		defer clear(token)
		if err != nil || len(token) == 0 {
			writeError(w, h.Logger, errUnauthenticated)
			return
		}
		principal, err := h.Authenticator.Authenticate(r.Context(), token)
		if err != nil {
			writeError(w, h.Logger, err)
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), principalKey{}, principal)))
	})
}

type principalKey struct{}

// principalFrom returns the principal authenticate stored, or the zero principal, which grants nothing.
func principalFrom(r *http.Request) authorization.Principal {
	principal, _ := r.Context().Value(principalKey{}).(authorization.Principal)
	return principal
}

// refuseUncleanPaths runs before the mux, which would otherwise redirect an
// unclean path and let a write land on a path the client never named.
func (h *Handlers) refuseUncleanPaths(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Matched on the cleaned path, where the redirect would land: an empty
		// segment before the route (/v1//policies/dev) hides it from the raw one.
		cleaned := path.Clean(r.URL.Path)
		if cleaned != r.URL.Path {
			for _, guarded := range uncleanPathErrors {
				// The added slash also catches a path that cleans to the collection itself (/v1/entities/x/..).
				if strings.HasPrefix(cleaned+"/", guarded.prefix) {
					writeError(w, h.Logger, guarded.err)
					return
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

// uncleanPathErrors names, per route, the error an unclean path landing under it is refused with.
var uncleanPathErrors = []struct {
	prefix string
	err    error
}{
	{"/v1/secrets/", secret.ErrInvalidPath},
	{"/v1/policies/", authorization.ErrInvalidName},
	{"/v1/entities/", identity.ErrInvalidEntityID},
	{"/v1/groups/", identity.ErrInvalidGroupID},
}
