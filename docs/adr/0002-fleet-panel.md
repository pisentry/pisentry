# ADR 0002: Fleet panel and MCP

- Status: Proposed
- Issue: #69

## Context

pisentry has no fleet view unless you run Prometheus and Grafana. With a few Pis on plain systemd you get a report per host, and nothing tells you an agent went quiet, which is the first thing an attacker with root makes happen.

People also want to ask an AI assistant what is going on and have it help fix what it finds. ServerOS does both with one design: a panel, a daemon on each server that takes orders from it, and an MCP server on the panel.

For pisentry that design has one problem. The agent runs as root on every host. A panel that can send it commands is the most valuable target on the network: whoever takes the panel gets root on the fleet. pisentry only watches, so it never needs to take orders.

## Decision

### Two products

- **pisentry**, the agent, stays in this repo and keeps its rules: one static binary, Go standard library only, no web UI and no listener beyond `/metrics`.
- **pisentry-panel** lives in a new repo, `pisentry/panel`. It is one Go binary with the web UI and SQLite embedded (pure Go driver, no cgo), so it runs on a Pi and installs like the agent. It ships as a release binary, a Docker image and a k3s manifest. It may use third-party modules; the agent may not.

Event Schema v1 is the only contract between them.

### Agents push, the panel receives

```
 host (root)                                    panel
 +-----------------------------+   HTTPS POST   +-----------------------------+
 | pisentry                    |  events and    | pisentry-panel              |
 |   detectors -> outbox ----------------------->  /ingest   (agent token)    |
 |                             |  heartbeats    |  web UI    (user session)   |
 | pisentry mcp  (stdio)       |                |  /mcp      (read-only token)|
 |   read tools, typed fixes   |   nothing is   |                             |
 +-------------^---------------+   sent back    +--------------^--------------+
               |                                               |
       MCP client on the host                        MCP client anywhere
       (or over ssh), asks the                       "what's going on across
       user before each fix                           my Pis?"
```

The agent sends events and heartbeats through the durable outbox (#67) to the panel URL. The panel never opens a connection to an agent, and no response the panel returns changes what the agent does. Active response (#23, #24) stays local to each host; the panel will never trigger it.

### Auth

- **Agents:** the panel issues a token per host from "Add host", shown once as an install command (`install.sh --panel URL --panel-token TOKEN`). The panel stores only a SHA-256 of it. Rotation issues a second token and accepts both for 24 hours. Deleting the host revokes it. HTTPS is required unless the panel URL is loopback. Mutual TLS can come later without changing the agent's output.
- **People:** local accounts with hashed passwords, and TOTP before 1.0.
- **MCP clients:** per-user API tokens, read-only.

### Storage

SQLite in the panel's data dir. Events are kept 30 days by default with a per-host cap, and daily Top 10 counts for a year. Both are settings.

### Quiet agents

The agent sends a heartbeat every 60 seconds with its version, rules loaded, packs on, learning time left and the doctor (#68) summary. Three missed heartbeats mark the host quiet in the UI and send the panel's own alert. Last event time is not used: a healthy host can go days with no events.

### AI through MCP

There are two MCP servers, and only the local one can change anything.

**`pisentry mcp` on each host.** It speaks MCP over stdio and is started by the MCP client, locally or with `ssh pi sudo pisentry mcp`. It never listens on the network. It is a thin layer over CLI commands, so a person and an agent apply a fix the same way.

- Read tools: status, recent events, explain an event (rule, matched fields, MITRE, known false positives), audit, doctor, categories.
- Fix tools, each also a CLI command:
  - add an exception to a rule (written to `rules.d`, checked by the same loader, then reloaded)
  - turn a pack off or on
  - send a test alert

  A fix tool returns the change as a diff first and applies it only on a second call with `confirm: true`, on top of the approval the MCP client already asks for. `pisentry mcp -read-only` drops the fix tools.
- Exceptions only suppress, so an exception added through MCP is itself a way to hide an attack. Every fix raises a PS00 event naming the rule and the change, which reaches the panel like any other event. MCP cannot add exceptions to pisentry's own tamper rules (stopping the agent, wiping its logs).
- No shell, no killing processes, no firewall changes. Fixing the host itself, such as removing a cron entry or closing a port, is the assistant's job through its own tools and the user's approval. pisentry supplies the evidence and the doctor's fix command.

**`/mcp` on the panel.** Streamable HTTP, read-only: fleet status, quiet hosts, events by host, category and time, Top 10, host detail and explain. It answers "what's going on" across the fleet and names the host and the command to run there. It has no tools that change anything, and none that relay to agents.

A chat box in the panel UI is out of scope for panel v0.1. When it comes, it calls the same read-only tools with the user's own model key.

### Event Schema versioning

Within v1, fields are only added. Consumers ignore fields they don't know. Removing a field or changing its meaning is v2. The panel accepts the current and the previous major version, so agents and panel can be upgraded in either order.

### Deployment

The panel listens on one HTTPS port (8443 by default) for ingest, the UI and `/mcp`, using a certificate you give it or plain HTTP on loopback behind a reverse proxy. The agent gains a `panel` output and the two `install.sh` flags, nothing else.

## Rejected options

- **A control panel like ServerOS**, where the panel sends commands to agents. Taking the panel would mean root on every host.
- **Panel MCP tools that relay fixes to agents.** The same control channel under another name.
- **An MCP listener on the agent.** New network attack surface on a root process, when stdio over ssh already reaches it.
- **The panel inside the agent binary, or a second binary in this repo.** The agent would carry web UI code, or this module would need dependencies the agent must not have.
- **JSON files instead of SQLite.** Fine for one host, but fleet queries by time and category need indexes.

## Consequences

- Fixes need a person or an assistant on the host. That is slower than clicking in the panel, and it is the point.
- The panel is a second product to release, with its own versions and security reports.
- Event Schema v1 becomes a public contract and needs the versioning rules above.
- The panel can't confirm a fix worked until the host's next heartbeat or event.

## Follow-ups

- `pisentry mcp` with read tools and typed fixes (v0.3.0)
- The agent's `panel` output, heartbeats and `install.sh --panel` / `--panel-token` (v0.3.1)
- `pisentry/panel` v0.1: ingest, host list with quiet hosts, fleet Top 10, event browser, accounts, read-only `/mcp`, Docker image (v0.3.1)
