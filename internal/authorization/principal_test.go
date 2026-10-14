package authorization_test

import (
	"testing"

	"github.com/dimitrijegasic/seal-gate/internal/authorization"
)

const entityID = "0123456789abcdef0123456789abcdef"

func TestPrincipal(t *testing.T) {
	t.Run("the root principal is named root", func(t *testing.T) {
		got := authorization.NewRootPrincipal().Identity()

		if want := "root"; got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("an entity principal is named by its entity ID", func(t *testing.T) {
		got := authorization.NewEntityPrincipal(entityID, "dev").Identity()

		if got != entityID {
			t.Errorf("got %q, want %q", got, entityID)
		}
	})

	t.Run("the zero principal is no one", func(t *testing.T) {
		got := authorization.Principal{}.Identity()

		if got != "" {
			t.Errorf("got %q, want %q", got, "")
		}
	})
}
