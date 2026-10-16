# seal-gate

A secrets-management service with Shamir-based unsealing, written in Go as a
bachelor's thesis project and loosely modelled on HashiCorp Vault.

Every value is encrypted before it reaches storage, under a key that is itself
stored only encrypted, by a root key that is never stored. At initialization
the root key is split into shares with Shamir's secret sharing. Every start
leaves the service sealed until a threshold of those same shares is handed in.
Once unsealed, it stores and generates secrets, controls access to them with
path-based policies over entities, groups and tokens, expires and rotates them
on a schedule, and writes an audit record of every request to an API route.

## Quick start

Needs Go (the version in `go.mod`), `curl` and a POSIX shell.

Build into an empty directory and start the server there. It listens on
`127.0.0.1:8080` and stays in the foreground:

```sh
DEMO=$(mktemp -d)
go build -o "$DEMO/" ./cmd/seal-gate
cd "$DEMO" && ./seal-gate
```

In a second terminal, check the status. A new server is neither initialized
nor unsealed:

```sh
curl -s http://127.0.0.1:8080/v1/sys/status
# {"initialized":false,"sealed":true,"progress":0}
```

Initialize it with three shares, any two of which unseal it. The response is
the only time the shares and the root token are shown:

```sh
curl -s -X POST http://127.0.0.1:8080/v1/sys/init \
  -H 'Content-Type: application/json' -d '{"shares":3,"threshold":2}'
# {"shares":["<share 1>","<share 2>","<share 3>"],"root_token":"<root token>"}
```

Copy two of the shares and the token into variables, then unseal with one
share at a time. `progress` counts the shares so far:

```sh
SHARE1='<share 1>'
SHARE2='<share 2>'
TOKEN='<root token>'

curl -s -X POST http://127.0.0.1:8080/v1/sys/unseal \
  -H 'Content-Type: application/json' -d "{\"share\":\"$SHARE1\"}"
# {"initialized":true,"sealed":true,"shares":3,"threshold":2,"progress":1}

curl -s -X POST http://127.0.0.1:8080/v1/sys/unseal \
  -H 'Content-Type: application/json' -d "{\"share\":\"$SHARE2\"}"
# {"initialized":true,"sealed":false,"shares":3,"threshold":2,"progress":0}
```

Write a secret and read it back. Values travel as base64, and the token is
sent as it was returned:

```sh
curl -s -X PUT http://127.0.0.1:8080/v1/secrets/app/db-password \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d "{\"value\":\"$(printf 'hunter2' | base64)\"}"

curl -s http://127.0.0.1:8080/v1/secrets/app/db-password \
  -H "Authorization: Bearer $TOKEN"
# {"value":"aHVudGVyMg=="}

echo 'aHVudGVyMg==' | base64 -d
# hunter2
```

Seal it again. The key is dropped from memory, and the same read is refused
until the service is unsealed again:

```sh
curl -s -X POST http://127.0.0.1:8080/v1/sys/seal -H "Authorization: Bearer $TOKEN"

curl -s http://127.0.0.1:8080/v1/secrets/app/db-password \
  -H "Authorization: Bearer $TOKEN"
# {"errors":["the system is sealed"]}
```

Stop the server with Ctrl+C. The demo directory now holds the encrypted
database, `seal-gate.db`, and the audit log, `seal-gate-audit.log`. Started
again in the same directory, the server comes back sealed, with the secret
still there.

The full HTTP API (policies, entities, groups, tokens, password login,
generated secrets and rotation) is described in
[api/openapi.yaml](api/openapi.yaml).

## Configuration

Two settings come from the environment. Everything else is a built-in
default, fixed in `internal/config/load.go`:

| Setting | Value |
|---|---|
| `SEAL_GATE_STORAGE_TYPE` | `bolt` (default), `postgres` or `memory` |
| `SEAL_GATE_STORAGE_URL` | the Postgres connection URL; used only by `postgres` |
| bolt file | `seal-gate.db`, in the working directory |
| listen address | `127.0.0.1:8080` |
| HTTP timeouts | 2 s to read headers, 5 s to read, 5 s to write, 5 s to shut down |
| encryption | AES-256-GCM |
| audit | one file, `seal-gate-audit.log`; a request fails if its record cannot be written within 1 s |
| lifecycle worker | sweeps for expired and due secrets and tokens every minute |
| tokens | issued tokens live 1 hour by default, 24 hours at most; the root token does not expire |
| logs | JSON on stdout, at `info` |

`memory` keeps nothing across a restart, so it suits tests and trying the API
out. To store in Postgres, set both variables, so the password in the URL
never sits in a file:

```sh
SEAL_GATE_STORAGE_TYPE=postgres
SEAL_GATE_STORAGE_URL='postgres://seal:<password>@db.example:5432/seal'
```

The backend keeps one table, `seal_gate`, created on start. Run one instance
per database: Postgres, unlike bolt's file lock, does not stop a second one.

## Layout

```text
cmd/seal-gate/          the binary; main() stays small
internal/
├── app/                composition root — builds the graph, holds no rules
├── config/             typed configuration, loaded but never applied here
├── system/             seal/unseal/init state machine, active-key lifetime
├── identity/           entities, groups, credentials, tokens — who is calling
├── authorization/      path-based ACL policies — what they may do
├── secret/             secret CRUD, generation and rotation; takes no cipher
├── lifecycle/          the worker: when secrets and tokens expire or rotate
├── cryptography/       primitives: AEAD, Shamir, key wrapping, password hashing
├── barrier/            the encryption boundary; everything below is ciphertext
├── repository/         the one implementation of every domain repository
├── storage/            four-method physical backends
│   ├── memory/         tests and development
│   ├── bolt/           embedded B+tree, the local default
│   ├── postgres/       SQL used deliberately as dumb KV
│   │   └── postgrestest/  per-test schemas for tests
│   └── conformance/    the definition of backend support
├── audit/              events and the fan-out recorder
│   └── file/           the file sink
└── httpapi/            routing, JSON, auth middleware, error mapping
api/openapi.yaml        the HTTP contract
tools/graphd/           live package graph + import rule enforcement
```

### Planned, not built

These were in the design and were cut for time. Nothing in the code depends
on them:

- **An etcd backend.** Postgres already shows a networked backend behind the
  same four-method contract.
- **In-memory indexes.** Every lookup is a direct read by key, and listing is
  a prefix scan, which is enough at this project's scale.
- **Rekey**, replacing the unseal shares without re-encrypting what is stored.
- **Locking key memory** and suppressing core dumps. Linux only, and not
  developed on Linux.

Running more than one instance (failover, standby) was left out by design,
not for time.

## How it was built

Test-first throughout: each behaviour starts as a failing test, and code and
its tests land in the same pull request. An issue is never split into one
that writes an implementation and a later one that tests it: merged behaviour
that nothing asserts is not finished work, and a test written a milestone
later gets written against the code instead of the requirement.

The exception is a test no red-green cycle can drive. `-race` needs a C
compiler, which the development machine did not have, so it runs only in CI,
on every pull request.

## Checks

### On save — automatic

The VS Code Go extension formats the file (gofmt, imports) and underlines
`go vet` and staticcheck findings. Fix what is underlined.

### Before committing

```sh
gofmt -l .                                   # must print nothing
go build ./...
go vet ./...
go test ./...
cd tools/graphd && go test -count=1 ./...    # import rules
```

`-count=1` is not optional: graphd runs `go list` on another directory tree,
which the test cache cannot see, so a cached pass can be stale.

The postgres backend's tests need a server, named by `SEAL_GATE_POSTGRES_URL`;
without it they skip. Each test gets a schema of its own, so one database
serves every package at once:

```sh
docker run -d --name seal-gate-pg -e POSTGRES_HOST_AUTH_METHOD=trust -p 127.0.0.1:5432:5432 postgres:18
export SEAL_GATE_POSTGRES_URL='postgres://postgres@localhost:5432/postgres?sslmode=disable'
```

### Benchmarks

`go test ./...` never runs them. Each one reports allocations; the postgres
rows need `SEAL_GATE_POSTGRES_URL`, as its tests do, and skip without it:

```sh
go test -run '^$' -bench . ./...
```

### Coverage

A number to read, not a gate. Each package counts only its own tests, so one
without any reads 0%. CI writes the same numbers as a table to the job summary:

```sh
go test -coverprofile=coverage.out ./...
go tool cover -func=coverage.out | tail -1     # total
go tool cover -html=coverage.out               # per line, in the browser
```

### Before opening a PR

```sh
go run honnef.co/go/tools/cmd/staticcheck@v0.8.1 ./...
go run golang.org/x/vuln/cmd/govulncheck@v1.8.0 ./...
```

Use the versions pinned in `.github/workflows/ci.yml`. CI also runs the tests
with `-race`, which needs cgo and a C compiler locally.

### On the PR — automatic

CI repeats all of the above, with `-race` and against a Postgres server, and
runs each benchmark once so a broken one fails. Then CodeQL and Copilot
review run. Merging needs the `Test` and `Architecture` checks to pass.

### Live package graph

```sh
cd tools/graphd && go run . -dir ../..       # http://127.0.0.1:7717
```
