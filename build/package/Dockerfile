FROM golang:1.26.6 AS build

COPY go.mod /src/go.mod
COPY go.sum /src/go.sum
WORKDIR /src
RUN go mod download

COPY cmd /src/cmd
COPY internal /src/internal

RUN go test ./...

# Pure Go throughout — the SQLite driver is cgo-free — so the binary needs
# nothing from the image it is copied into.
RUN CGO_ENABLED=0 go build -o /forti-control ./cmd/forti-control


FROM ubuntu:24.04

EXPOSE 8081

COPY --from=build /forti-control /usr/local/bin/forti-control

# The controller writes the configuration files and reads the status files, so
# its mounts are the mirror image of a service's: /config read-write, /status
# read-only. /data is its own, and holds the database and the snapshots.
#
# A fresh named volume takes its ownership from the image that first mounts
# it, and everything here runs as nobody, so these have to exist with the
# right owner before that happens.
RUN mkdir -p /config /status /data && chown nobody:nogroup /config /status /data

USER nobody

ENTRYPOINT [ "/usr/local/bin/forti-control" ]
CMD [ "-listen", ":8081", "-config-dir", "/config", "-status-dir", "/status", "-data-dir", "/data" ]
