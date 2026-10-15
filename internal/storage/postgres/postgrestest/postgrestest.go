// Package postgrestest gives tests an empty schema on the server named by SEAL_GATE_POSTGRES_URL.
package postgrestest

import (
	"context"
	"crypto/rand"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

// variable names the test server; tests that need it skip without it.
const variable = "SEAL_GATE_POSTGRES_URL"

// SchemaURL gives each test an empty schema of its own, since packages run in parallel against one server.
func SchemaURL(t *testing.T) string {
	t.Helper()
	server := os.Getenv(variable)
	if server == "" {
		t.Skipf("%s not set", variable)
	}

	conn, err := pgx.Connect(t.Context(), server)
	if err != nil {
		// Not err: pgx's redaction misses malformed URLs, so it can print the password.
		t.Fatalf("Connect: cannot reach the server %s names", variable)
	}
	defer conn.Close(context.Background())

	// Lower case: search_path folds an unquoted name, and the URL cannot quote it.
	schema := "test_" + strings.ToLower(rand.Text())
	if _, err := conn.Exec(t.Context(), "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize()); err != nil {
		t.Fatalf("CREATE SCHEMA: %v", err)
	}
	t.Cleanup(func() { dropSchema(t, server, schema) })

	u, err := url.Parse(server)
	if err != nil {
		// Not err: url.Parse repeats the raw URL, password included.
		t.Fatalf("Parse: %s is not a URL", variable)
	}
	query := u.Query()
	query.Set("search_path", schema)
	u.RawQuery = query.Encode()
	return u.String()
}

// dropSchema runs in cleanup, after t.Context() is cancelled.
func dropSchema(t *testing.T, server, schema string) {
	t.Helper()
	ctx := context.Background()

	conn, err := pgx.Connect(ctx, server)
	if err != nil {
		t.Errorf("Connect: cannot reach the server %s names to drop %s", variable, schema)
		return
	}
	defer conn.Close(ctx)

	if _, err := conn.Exec(ctx, "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE"); err != nil {
		t.Errorf("DROP SCHEMA: %v", err)
	}
}
