# pisentry panel

One place to see every Pi running pisentry: which hosts are reporting, which went quiet, the Top 10 across the fleet and every event. Agents push to the panel; the panel never connects to them or sends them commands. [ADR 0002](../docs/adr/0002-fleet-panel.md) has the reasoning.

**Status: early.** The panel runs and takes events, but the agent can't send to it yet (#76), and accounts, "Add a Pi" in the UI and the read-only MCP endpoint are still to come (#77).

## What's here

- `cmd/pisentry-panel`: one binary with the web UI and SQLite built in. No cgo, so it cross-compiles for every Pi.
- `POST /ingest`: Event Schema v1 events from agents, as a JSON array or one event per line, with a per-host bearer token. A batch is stored whole or not at all, and an event sent twice is stored once.
- `GET /api/hosts`, `/api/events`, `/api/events/{host}/{id}`, `/api/top10`: what the UI reads, behind the admin token.
- `web/`: the Vue app, built into `internal/web/dist` and embedded in the binary.

## Try it

```bash
make ui build
./pisentry-panel host add -data ./data kubepi     # prints the host's token once
./pisentry-panel admin-token -data ./data         # the token the UI asks for
./pisentry-panel serve -data ./data               # http://127.0.0.1:8443
```

Send an event as that host:

```bash
curl -H "Authorization: Bearer psp_..." --data-binary @event.json http://127.0.0.1:8443/ingest
```

The panel refuses plain HTTP on anything but loopback, because host and admin tokens would cross the network in the clear. Give it `-tls-cert` and `-tls-key`, or keep it on `127.0.0.1` behind a reverse proxy that does TLS.

| Flag | Default | |
|---|---|---|
| `-listen` | `127.0.0.1:8443` | |
| `-data` | `/var/lib/pisentry-panel` | SQLite database and settings |
| `-tls-cert`, `-tls-key` | | PEM files |
| `-quiet-after` | `3m` | A host with nothing sent for this long is shown as quiet |
| `-retention` | `720h` | Events older than this are deleted hourly |

`deploy/pisentry-panel.service` runs it as an unprivileged `pisentry-panel` user. The `Dockerfile` builds a multi-arch image that expects a certificate in `/tls`.

## Development

Go 1.27 and Node 22.

```bash
make vet test        # Go checks; the UI isn't needed for tests
make ui              # build the UI into the Go package
cd web && npm run dev   # UI with hot reload, proxying /api to a panel on 127.0.0.1:8443
```

This is its own Go module so the agent keeps zero dependencies. Nothing in the agent imports the panel.
