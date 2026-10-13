package httpapi

import (
	"context"
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
	Seal(ctx context.Context)
	Status(ctx context.Context) (system.Status, error)
}

// SecretService is secret storage as the handlers use it.
type SecretService interface {
	Put(ctx context.Context, path string, value []byte) error
	Get(ctx context.Context, path string) ([]byte, error)
	Delete(ctx context.Context, path string) error
	List(ctx context.Context, prefix string) ([]string, error)
}

// PolicyService is policy storage as the handlers use it.
type PolicyService interface {
	Put(ctx context.Context, policy authorization.Policy) error
	Get(ctx context.Context, name string) (authorization.Policy, error)
	Delete(ctx context.Context, name string) error
}

// EntityService is entity storage as the handlers use it.
type EntityService interface {
	CreateEntity(ctx context.Context, entity identity.Entity) (string, error)
	GetEntity(ctx context.Context, id string) (identity.Entity, error)
	UpdateEntity(ctx context.Context, entity identity.Entity) error
	DeleteEntity(ctx context.Context, id string) error
}

// TokenService is token issuing as the handlers use it.
type TokenService interface {
	CreateToken(ctx context.Context, entityID string) ([]byte, error)
}

// GroupService is group storage as the handlers use it.
type GroupService interface {
	CreateGroup(ctx context.Context, group identity.Group) (string, error)
	GetGroup(ctx context.Context, id string) (identity.Group, error)
	UpdateGroup(ctx context.Context, group identity.Group) error
	DeleteGroup(ctx context.Context, id string) error
}

// Handlers holds what the HTTP handlers call.
type Handlers struct {
	System SystemService
	Secret SecretService
	Policy PolicyService
	Entity EntityService
	Token  TokenService
	Group  GroupService
	Logger *slog.Logger
}

func NewRouter(h *Handlers) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("POST /v1/sys/init", h.handleInit)
	mux.HandleFunc("POST /v1/sys/unseal", h.handleUnseal)
	mux.HandleFunc("POST /v1/sys/seal", h.handleSeal)
	mux.HandleFunc("GET /v1/sys/status", h.handleStatus)
	mux.HandleFunc("GET /v1/sys/health", h.handleHealth)

	mux.HandleFunc("GET /v1/secrets", h.handleListSecrets)
	mux.HandleFunc("PUT /v1/secrets/{path...}", h.handlePutSecret)
	mux.HandleFunc("GET /v1/secrets/{path...}", h.handleGetSecret)
	mux.HandleFunc("DELETE /v1/secrets/{path...}", h.handleDeleteSecret)

	mux.HandleFunc("PUT /v1/policies/{name}", h.handlePutPolicy)
	mux.HandleFunc("GET /v1/policies/{name}", h.handleGetPolicy)
	mux.HandleFunc("DELETE /v1/policies/{name}", h.handleDeletePolicy)

	mux.HandleFunc("POST /v1/entities", h.handleCreateEntity)
	mux.HandleFunc("GET /v1/entities/{id}", h.handleGetEntity)
	mux.HandleFunc("PUT /v1/entities/{id}", h.handleUpdateEntity)
	mux.HandleFunc("DELETE /v1/entities/{id}", h.handleDeleteEntity)
	mux.HandleFunc("POST /v1/entities/{id}/tokens", h.handleCreateToken)

	mux.HandleFunc("POST /v1/groups", h.handleCreateGroup)
	mux.HandleFunc("GET /v1/groups/{id}", h.handleGetGroup)
	mux.HandleFunc("PUT /v1/groups/{id}", h.handleUpdateGroup)
	mux.HandleFunc("DELETE /v1/groups/{id}", h.handleDeleteGroup)

	return h.refuseUncleanPaths(mux)
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
