package httpapi

import (
	"context"
	"encoding/base64"
	"log/slog"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/dimitrijegasic/seal-gate/internal/audit"
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
	Put(ctx context.Context, principal authorization.Principal, path string, value []byte, ttl time.Duration) error
	Get(ctx context.Context, principal authorization.Principal, path string) (secret.Entry, error)
	Delete(ctx context.Context, principal authorization.Principal, path string) error
	List(ctx context.Context, principal authorization.Principal, prefix string) ([]string, error)
	Generate(ctx context.Context, principal authorization.Principal, path string, length int, ttl time.Duration) ([]byte, error)
	Rotate(ctx context.Context, principal authorization.Principal, path string) ([]byte, error)
}

// PolicyService is policy storage as the handlers use it.
type PolicyService interface {
	Put(ctx context.Context, principal authorization.Principal, policy authorization.Policy) error
	Get(ctx context.Context, principal authorization.Principal, name string) (authorization.Policy, error)
	Delete(ctx context.Context, principal authorization.Principal, name string) error
	List(ctx context.Context, principal authorization.Principal) ([]string, error)
}

// EntityService is entity storage as the handlers use it.
type EntityService interface {
	CreateEntity(ctx context.Context, principal authorization.Principal, entity identity.Entity) (string, error)
	GetEntity(ctx context.Context, principal authorization.Principal, id string) (identity.Entity, error)
	UpdateEntity(ctx context.Context, principal authorization.Principal, entity identity.Entity) error
	DeleteEntity(ctx context.Context, principal authorization.Principal, id string) error
	ListEntities(ctx context.Context, principal authorization.Principal) ([]identity.EntitySummary, error)
}

// TokenService is token issuing, revoking and rotating as the handlers use it.
type TokenService interface {
	CreateToken(ctx context.Context, principal authorization.Principal, entityID string, ttl time.Duration) ([]byte, time.Time, error)
	RevokeToken(ctx context.Context, token []byte) error
	RotateToken(ctx context.Context, token []byte, ttl time.Duration) ([]byte, time.Time, error)
}

// GroupService is group storage as the handlers use it.
type GroupService interface {
	CreateGroup(ctx context.Context, principal authorization.Principal, group identity.Group) (string, error)
	GetGroup(ctx context.Context, principal authorization.Principal, id string) (identity.Group, error)
	UpdateGroup(ctx context.Context, principal authorization.Principal, group identity.Group) error
	DeleteGroup(ctx context.Context, principal authorization.Principal, id string) error
	ListGroups(ctx context.Context, principal authorization.Principal) ([]identity.GroupSummary, error)
}

// UserService is user storage and password login as the handlers use it.
type UserService interface {
	SetUser(ctx context.Context, principal authorization.Principal, name, entityID string, password []byte) error
	DeleteUser(ctx context.Context, principal authorization.Principal, name string) error
	ListUsers(ctx context.Context, principal authorization.Principal) ([]identity.UserSummary, error)
	Login(ctx context.Context, name string, password []byte) ([]byte, time.Time, error)
}

// Authenticator turns a request's token into the principal it acts as; an unknown token must be identity.ErrInvalidToken, as anything else is a 500.
type Authenticator interface {
	Authenticate(ctx context.Context, token []byte) (authorization.Principal, error)
}

// Auditor records audit events; a failure to record a request event refuses that request.
type Auditor interface {
	Record(ctx context.Context, event audit.Event) error
}

// Clock is what audit events are stamped with.
type Clock interface {
	Now() time.Time
}

// Handlers holds what the HTTP handlers call.
type Handlers struct {
	Auditor       Auditor
	Clock         Clock
	Authenticator Authenticator
	System        SystemService
	Secret        SecretService
	Policy        PolicyService
	Entity        EntityService
	Token         TokenService
	Group         GroupService
	User          UserService
	Logger        *slog.Logger
}

func NewRouter(h *Handlers) http.Handler {
	mux := http.NewServeMux()

	// Open: they must work before any token exists, or while none can be checked.
	mux.Handle("POST /v1/sys/init", h.open(h.handleInit))
	mux.Handle("POST /v1/sys/unseal", h.open(h.handleUnseal))
	mux.Handle("GET /v1/sys/status", h.open(h.handleStatus))
	mux.Handle("GET /v1/sys/health", h.open(h.handleHealth))
	mux.Handle("POST /v1/auth/login", h.open(h.handleLogin))

	mux.Handle("POST /v1/sys/seal", h.authenticated(h.handleSeal))

	mux.Handle("POST /v1/auth/token/revoke", h.authenticated(h.handleRevokeToken))
	mux.Handle("POST /v1/auth/token/rotate", h.authenticated(h.handleRotateToken))
	mux.Handle("GET /v1/auth/users", h.authenticated(h.handleListUsers))
	mux.Handle("PUT /v1/auth/users/{name}", h.authenticated(h.handleSetUser))
	mux.Handle("DELETE /v1/auth/users/{name}", h.authenticated(h.handleDeleteUser))

	mux.Handle("GET /v1/secrets", h.authenticated(h.handleListSecrets))
	mux.Handle("PUT /v1/secrets/{path...}", h.authenticated(h.handlePutSecret))
	mux.Handle("GET /v1/secrets/{path...}", h.authenticated(h.handleGetSecret))
	mux.Handle("DELETE /v1/secrets/{path...}", h.authenticated(h.handleDeleteSecret))
	mux.Handle("POST /v1/secrets/generate/{path...}", h.authenticated(h.handleGenerateSecret))
	mux.Handle("POST /v1/secrets/rotate/{path...}", h.authenticated(h.handleRotateSecret))

	mux.Handle("GET /v1/policies", h.authenticated(h.handleListPolicies))
	mux.Handle("PUT /v1/policies/{name}", h.authenticated(h.handlePutPolicy))
	mux.Handle("GET /v1/policies/{name}", h.authenticated(h.handleGetPolicy))
	mux.Handle("DELETE /v1/policies/{name}", h.authenticated(h.handleDeletePolicy))

	mux.Handle("GET /v1/entities", h.authenticated(h.handleListEntities))
	mux.Handle("POST /v1/entities", h.authenticated(h.handleCreateEntity))
	mux.Handle("GET /v1/entities/{id}", h.authenticated(h.handleGetEntity))
	mux.Handle("PUT /v1/entities/{id}", h.authenticated(h.handleUpdateEntity))
	mux.Handle("DELETE /v1/entities/{id}", h.authenticated(h.handleDeleteEntity))
	mux.Handle("POST /v1/entities/{id}/tokens", h.authenticated(h.handleCreateToken))

	mux.Handle("GET /v1/groups", h.authenticated(h.handleListGroups))
	mux.Handle("POST /v1/groups", h.authenticated(h.handleCreateGroup))
	mux.Handle("GET /v1/groups/{id}", h.authenticated(h.handleGetGroup))
	mux.Handle("PUT /v1/groups/{id}", h.authenticated(h.handleUpdateGroup))
	mux.Handle("DELETE /v1/groups/{id}", h.authenticated(h.handleDeleteGroup))

	return h.refuseUncleanPaths(mux)
}

// open audits a route that needs no token.
func (h *Handlers) open(next http.HandlerFunc) http.Handler {
	return h.audit(next)
}

// authenticated identifies the caller, audits the request, then refuses it unless the caller authenticated.
func (h *Handlers) authenticated(next http.HandlerFunc) http.Handler {
	// Audit sits between the halves: after identify, so it knows the principal;
	// before require, so it records the requests require refuses.
	return h.identify(h.audit(h.require(next)))
}

// authentication is what identify learned: a principal and the token it came from, or why there is none.
type authentication struct {
	principal authorization.Principal
	// Cleared by identify once the handler returns, so no handler keeps or clears it.
	token []byte
	err   error
}

type authenticationKey struct{}

// identify resolves the bearer token, if any, and stores the outcome for require; it refuses nothing.
func (h *Handlers) identify(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		result := authentication{err: errUnauthenticated}
		// The scheme is case-insensitive (RFC 7235); the token is not.
		scheme, encoded, _ := strings.Cut(r.Header.Get("Authorization"), " ")
		if strings.EqualFold(scheme, "Bearer") {
			token, err := base64.StdEncoding.DecodeString(encoded)
			// Deferred before the check: a rejected decode can still return the bytes it read.
			defer clear(token)
			if err == nil && len(token) > 0 {
				result.principal, result.err = h.Authenticator.Authenticate(r.Context(), token)
				if result.err == nil {
					result.token = token
				}
			}
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), authenticationKey{}, result)))
	})
}

// require refuses a request identify did not authenticate, before next runs.
func (h *Handlers) require(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		result, ok := r.Context().Value(authenticationKey{}).(authentication)
		// Without identify there is no outcome, and no outcome is no caller.
		if !ok {
			result.err = errUnauthenticated
		}
		if result.err != nil {
			writeError(w, h.Logger, result.err)
			return
		}
		next(w, r)
	})
}

// principalFrom returns the principal identify authenticated, or the zero principal, which grants nothing.
func principalFrom(r *http.Request) authorization.Principal {
	result, _ := r.Context().Value(authenticationKey{}).(authentication)
	if result.err != nil {
		return authorization.Principal{}
	}
	return result.principal
}

// tokenFrom returns the token identify authenticated, or nil; it is cleared once the request is served.
func tokenFrom(r *http.Request) []byte {
	result, _ := r.Context().Value(authenticationKey{}).(authentication)
	return result.token
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
	{"/v1/auth/users/", identity.ErrInvalidUsername},
}
