# Built as a static binary: bbolt and pgx are pure Go, so nothing needs cgo.
FROM golang:1.26.9 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/seal-gate ./cmd/seal-gate \
 && mkdir /out/data

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/seal-gate /usr/local/bin/seal-gate
COPY deploy/config.yaml deploy/postgres.yaml /etc/seal-gate/
# Owned by the nonroot user, so a fresh named volume mounted here is writable.
COPY --from=build --chown=65532:65532 /out/data /data
WORKDIR /data
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/seal-gate"]
CMD ["-config", "/etc/seal-gate/config.yaml"]
