package httpapi_test

import (
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/dimitrijegasic/seal-gate/internal/authorization"
	"github.com/dimitrijegasic/seal-gate/internal/httpapi"
)

const devPolicyJSON = `{"rules":[{"path":"secrets/dev/*","capabilities":["read","list"]}]}`

func devPolicy() authorization.Policy {
	return authorization.Policy{
		Name: "dev",
		Rules: []authorization.Rule{{
			Path:         "secrets/dev/*",
			Capabilities: []authorization.Capability{authorization.CapabilityRead, authorization.CapabilityList},
		}},
	}
}

func TestPolicy(t *testing.T) {
	t.Run("a written policy reaches the service with its name and rules", func(t *testing.T) {
		fake := &fakePolicy{}
		router := newRouter(&httpapi.Handlers{Authenticator: &fakeAuthenticator{}, Policy: fake})
		want := devPolicy()

		rec := do(t, router, http.MethodPut, "/v1/policies/dev", devPolicyJSON)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("status: got %d, want %d: %s", rec.Code, http.StatusNoContent, rec.Body)
		}

		if !reflect.DeepEqual(fake.putPolicy, want) {
			t.Errorf("got %+v, want %+v", fake.putPolicy, want)
		}
	})

	t.Run("a body naming the policy is refused", func(t *testing.T) {
		router := newRouter(&httpapi.Handlers{Authenticator: &fakeAuthenticator{}, Policy: &fakePolicy{}})

		rec := do(t, router, http.MethodPut, "/v1/policies/dev", `{"name":"admin","rules":[]}`)

		assertError(t, rec, http.StatusBadRequest, `unknown field in request body: "name"`)
	})

	t.Run("a field of the wrong type is refused without naming a Go type", func(t *testing.T) {
		router := newRouter(&httpapi.Handlers{Authenticator: &fakeAuthenticator{}, Policy: &fakePolicy{}})

		rec := do(t, router, http.MethodPut, "/v1/policies/dev", `{"rules":"x"}`)

		assertError(t, rec, http.StatusBadRequest, `field "rules" has the wrong type`)
	})

	t.Run("an absent rule list stores a policy with none", func(t *testing.T) {
		fake := &fakePolicy{}
		router := newRouter(&httpapi.Handlers{Authenticator: &fakeAuthenticator{}, Policy: fake})

		rec := do(t, router, http.MethodPut, "/v1/policies/dev", `{}`)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("status: got %d, want %d: %s", rec.Code, http.StatusNoContent, rec.Body)
		}

		if len(fake.putPolicy.Rules) != 0 {
			t.Errorf("got %d rules, want 0", len(fake.putPolicy.Rules))
		}
	})

	t.Run("a stored policy is returned with its rules", func(t *testing.T) {
		router := newRouter(&httpapi.Handlers{Authenticator: &fakeAuthenticator{}, Policy: &fakePolicy{getPolicy: devPolicy()}})
		want := policyBody{Rules: []ruleBody{{Path: "secrets/dev/*", Capabilities: []string{"read", "list"}}}}

		rec := do(t, router, http.MethodGet, "/v1/policies/dev", "")
		if rec.Code != http.StatusOK {
			t.Fatalf("status: got %d, want %d: %s", rec.Code, http.StatusOK, rec.Body)
		}
		got := decode[policyBody](t, rec)

		if !reflect.DeepEqual(got, want) {
			t.Errorf("got %+v, want %+v", got, want)
		}
	})

	t.Run("a policy without rules is returned with an empty list", func(t *testing.T) {
		router := newRouter(&httpapi.Handlers{Authenticator: &fakeAuthenticator{}, Policy: &fakePolicy{getPolicy: authorization.Policy{Name: "dev"}}})
		want := `{"rules":[]}`

		rec := do(t, router, http.MethodGet, "/v1/policies/dev", "")
		if rec.Code != http.StatusOK {
			t.Fatalf("status: got %d, want %d: %s", rec.Code, http.StatusOK, rec.Body)
		}
		got := strings.TrimSpace(rec.Body.String())

		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("a delete answers no content", func(t *testing.T) {
		router := newRouter(&httpapi.Handlers{Authenticator: &fakeAuthenticator{}, Policy: &fakePolicy{}})

		rec := do(t, router, http.MethodDelete, "/v1/policies/dev", "")

		if rec.Code != http.StatusNoContent {
			t.Errorf("status: got %d, want %d: %s", rec.Code, http.StatusNoContent, rec.Body)
		}
		if rec.Body.Len() != 0 {
			t.Errorf("body: got %q, want empty", rec.Body)
		}
	})

	t.Run("each operation passes the name to the service", func(t *testing.T) {
		tests := []struct {
			name   string
			method string
		}{
			{"get", http.MethodGet},
			{"delete", http.MethodDelete},
		}

		want := "dev"
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				fake := &fakePolicy{}
				router := newRouter(&httpapi.Handlers{Authenticator: &fakeAuthenticator{}, Policy: fake})

				do(t, router, tt.method, "/v1/policies/"+want, "")

				if fake.name != want {
					t.Errorf("got %q, want %q", fake.name, want)
				}
			})
		}
	})

	t.Run("each operation passes the authenticated principal to the service", func(t *testing.T) {
		tests := []struct {
			name   string
			method string
			body   string
		}{
			{"get", http.MethodGet, ""},
			{"put", http.MethodPut, devPolicyJSON},
			{"delete", http.MethodDelete, ""},
		}

		want := authorization.NewEntityPrincipal(entityID, "dev")
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				fake := &fakePolicy{}
				router := newRouter(&httpapi.Handlers{Authenticator: &fakeAuthenticator{principal: want}, Policy: fake})

				do(t, router, tt.method, "/v1/policies/dev", tt.body)

				if !reflect.DeepEqual(fake.principal, want) {
					t.Errorf("got %+v, want %+v", fake.principal, want)
				}
			})
		}
	})

	t.Run("a denied operation is forbidden", func(t *testing.T) {
		router := newRouter(&httpapi.Handlers{Authenticator: &fakeAuthenticator{}, Policy: &fakePolicy{err: authorization.ErrDenied}})

		rec := do(t, router, http.MethodGet, "/v1/policies/dev", "")

		assertError(t, rec, http.StatusForbidden, "permission denied")
	})

	t.Run("each operation reports the service's error", func(t *testing.T) {
		tests := []struct {
			name   string
			method string
			body   string
		}{
			{"put", http.MethodPut, devPolicyJSON},
			{"get", http.MethodGet, ""},
			{"delete", http.MethodDelete, ""},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				router := newRouter(&httpapi.Handlers{Authenticator: &fakeAuthenticator{}, Policy: &fakePolicy{err: authorization.ErrSealed}})

				rec := do(t, router, tt.method, "/v1/policies/dev", tt.body)

				assertError(t, rec, http.StatusServiceUnavailable, "the system is sealed")
			})
		}
	})

	t.Run("each domain error maps to its status and message", func(t *testing.T) {
		tests := []struct {
			name    string
			err     error
			status  int
			message string
		}{
			{"invalid name", authorization.ErrInvalidName, http.StatusBadRequest, "invalid policy name"},
			{"invalid rule", authorization.ErrInvalidRule, http.StatusBadRequest, "invalid policy rule"},
			{"not found", authorization.ErrNotFound, http.StatusNotFound, "policy not found"},
			// A corrupt record is the server's fault, not the client's.
			{"unreadable policy", authorization.ErrUnreadablePolicy, http.StatusInternalServerError, "internal error"},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				router := newRouter(&httpapi.Handlers{Authenticator: &fakeAuthenticator{}, Policy: &fakePolicy{err: tt.err}})

				rec := do(t, router, http.MethodGet, "/v1/policies/dev", "")

				assertError(t, rec, tt.status, tt.message)
			})
		}
	})
}
