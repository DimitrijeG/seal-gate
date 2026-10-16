# seal-gate

Secret Management Service with Shamir-Based Unsealing.

## Intended layout

```text
cmd/seal-gate/          the binary; main() stays small
internal/
├── app/                composition root — builds the graph, holds no rules
├── config/             typed configuration, loaded but never applied here
├── system/             seal/unseal/init state machine, active-key lifetime
├── identity/           entities, groups, credentials, tokens — who is calling
├── authorization/      path-based ACL policies — what they may do
├── secret/             secret CRUD; notably takes no cipher
├── lifecycle/          TTL, rotation, revocation, and the worker
├── cryptography/       primitives: AEAD, Shamir, key wrapping, hashing
├── barrier/            the encryption boundary; everything below is ciphertext
├── repository/         the one indexed implementation of every domain repo
│   └── index/          in-memory indexes; gate enforced by package boundary
├── storage/            four-method physical backends
│   ├── memory/         tests and development
│   ├── bolt/           embedded B+tree, the local default
│   ├── postgres/       SQL used deliberately as dumb KV
│   ├── etcd/           network store, over the HTTP gateway
│   └── conformance/    the definition of backend support
├── audit/              events, fan-out recorder, sinks
└── httpapi/            routing, JSON, auth middleware, error mapping
api/openapi.yaml        the HTTP contract
tools/graphd/           live package graph + import rule enforcement
```

## Storage

The default backend is bolt, a file in the working directory. To store in Postgres,
set both variables in the environment, so the password in the URL never sits
in a file:

```sh
SEAL_GATE_STORAGE_TYPE=postgres
SEAL_GATE_STORAGE_URL='postgres://seal:<password>@db.example:5432/seal'
```

The backend keeps one table, `seal_gate`, created on start. Run one instance
per database: postgres, unlike bolt's file lock, does not stop a second one.

## What a change includes

Code and its tests ship together, in the same pull request. An issue is never
split into one that writes an implementation and a later one that tests it:
merged behavior that nothing asserts is not finished work, and a test written
a milestone afterwards gets written against the code instead of against the
requirement it was supposed to pin down.

The exception is a test no red-green cycle can drive, and it gets a `test`
issue of its own. `-race` needs a C compiler, which a development machine
here is not assumed to have, so it runs only in CI, on every pull request.
Fuzzing has no natural end, so it runs against a time budget instead.

## Checks

### On save — automatic

The VS Code Go extension formats the file (gofmt, imports) and underlines
`go vet` and staticcheck findings. Fix what is underlined.

### Before committing

```sh
gofmt -l .                                   # must print nothing
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

CI repeats all of the above, then CodeQL and Copilot review run.
Merging needs the `Test` and `Architecture` checks to pass.

### Live package graph

```sh
cd tools/graphd && go run . -dir ../..       # http://127.0.0.1:7717
```
