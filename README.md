# forti-control

A web UI for [forti](https://github.com/metno/forti)'s configuration files.

Change a parameter mapping in a browser, hit Save, and the running service
picks it up. No redeploy, no restart, and no image rebuild.

## How it works

```
                 ┌───────────────┐
  browser ──────▶│ forti-control │  Go + htmx, local users,
                 └───────┬───────┘  snapshots + audit log
             writes │        │ reads
                    ▼        ▲
        /config/*.json   /status/*.json          (shared volume)
                    │        ▲
            watches │        │ writes
        ┌───────────┴────────┴────────────┐
        │ jsonfrontend   rawdataforecaster │  healthz
        └──────────────────────────────────┘
```

**The filesystem is the entire interface.** The controller has no network
connection to any forti service, no RPC, no service discovery, no credentials
for anything, and no Docker socket. It writes files and reads files.

That has one consequence worth stating plainly: **saved is not the same as
live.** The controller writes a file; the service decides whether it is usable,
because the service is the thing that has the schema. A save that the service
refuses leaves it serving the previous configuration, and the status panel
beside the editor is what tells you which of the two you are looking at.

`forti-control` has no Go dependency on forti. The contract between them is the
two JSON documents on the volume — the configuration, whose meaning only the
service knows, and the status file, whose shape is described in
`internal/status`.

## Running it

```
go run ./cmd/forti-control \
	-config-dir ./config -status-dir ./status -data-dir ./data \
	-listen :8081
```

On first start it creates an `admin` user. Set
`FORTI_CONTROL_ADMIN_PASSWORD` to choose the password, or leave it unset and
the controller generates one and prints it to the log, once. It will not
overwrite an existing user's password on a later start.

`-modules` names what to manage and which file each one reads:

```
-modules jsonfrontend,rawdataforecaster=forecast.json,healthz=probes.json
```

The names have to be ones this controller knows about, so nothing in a config
file can widen what the UI is able to write. The filename is settable because
a deployment runs `rawdataforecaster` once per product. Leave the flag off to
manage all three with their usual filenames.

`deploy/compose.yaml` runs it beside `jsonfrontend`. The mounts there are
deliberately asymmetric:

| | `/config` | `/status` |
|---|---|---|
| forti-control | read-write | read-only |
| a forti service | read-only | read-write |

so a bug on either side cannot damage what the other owns. Both containers run
as `nobody`; the images create these directories owned by `nobody` so that a
fresh named volume inherits it, which is the thing that makes a service able to
write its status at all.

## Two things it refuses to do quietly

Forti's characteristic bug is that wrong configuration produces silence rather
than an error, so the controller is careful not to add two more of its own:

- **A save made against a version that has moved is refused.** The editor
  carries the digest it was opened on. If somebody else saved in between,
  writing would drop their change with neither of them told, so the second
  save is rejected and says what happened.
- **A stale report is never shown against a new save.** `loaded_sha` is the
  version a service last *read*. When it does not match the file on disk, the
  errors in that report belong to an earlier version, and showing them would
  blame the save just made for the previous one's problems. The panel says it
  is waiting instead.

## What it stores

Three things, in `-data-dir`:

- **`control.db`** — users, sessions, and the audit log. SQLite, through a
  cgo-free driver.
- **`snapshots/<module>/`** — every version of every file the controller has
  ever written, named by timestamp and content digest.
- The audit log **references snapshots by digest** rather than storing what
  changed, so "who changed this, and what did it say before?" is one link away.

The digest is the plain sha256 of the file's bytes, which is also what a
service reports in `loaded_sha`. That shared digest is the whole
synchronisation mechanism: it is how the UI knows whether the version on disk
is the version in use.

At first startup the controller snapshots whatever configuration is already on
the volume. That version predates the controller and is the one nobody could
reconstruct once it had been overwritten.

## Testing

```
go test -race ./...
```

There is nothing to mock. The tests write real files into `t.TempDir()`, open
real SQLite databases, and drive real HTTP requests through the real handlers;
a "service" in a test is a status file written by hand, which is exactly what a
service is to the controller.
