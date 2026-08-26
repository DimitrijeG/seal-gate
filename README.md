# seal-gate

Secret Management Service with Shamir-Based Unsealing.

## Intended layout

```text
cmd/seal-gate/          the binary; main() stays small
internal/
├── app/                composition root — builds the graph, holds no rules
├── config/             typed configuration, loaded but never applied here
├── common/             Clock, and deliberately nothing else
├── system/             seal/unseal/init state machine, active-key lifetime
├── identity/           entities, groups, credentials, tokens — who is calling
├── authorization/      path-based ACL policies — what they may do
├── secrets/            secret CRUD; notably takes no cipher
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

## Checks

```sh
go build ./... && go vet ./... && gofmt -l .   # gofmt printing nothing is green
go test ./...

cd tools/graphd && go test -count=1 ./...      # architecture rules
cd tools/graphd && go run . -dir ../..         # live graph on :7717
```

`-count=1` is not optional: graphd shells out to `go list` against another
directory tree, which Go test caching cannot observe, so a cached pass can be
stale.
