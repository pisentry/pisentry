# Rule Schema v1

Detection rules are strict JSON bundles. The built-in bundle is [`deploy/rules/default.json`](../deploy/rules/default.json), embedded in the binary. Operators add or override rules with more bundles in `rules.dir` (default `/etc/pisentry/rules.d`, env `PISENTRY_RULES_DIR`).

The agent runs as root and parses these files, so the loader is attack surface. It is `encoding/json` with unknown fields rejected, hard size limits, and RE2 regexes compiled at load time. There is no YAML parser in the agent.

## Bundle

```json
{
  "schema_version": 1,
  "catalog": { "stratum_ports": [3333, 4444] },
  "rules": [ { "id": "...", "...": "..." } ]
}
```

| Field | Required | Notes |
|---|---|---|
| `schema_version` | yes | Must be `1`. |
| `rules` | one of the two | Up to 500 rules per file. |
| `catalog` | one of the two | Table-driven lists for detectors whose logic stays in Go: `stratum_ports`, `shell_names`, `backdoor_ports` (`{port, note}`), `fim_watches`, `gtfo_suid`, `pkg_managers`, `priv_groups`. A list in `rules.d` replaces the built-in list of the same name. |

## Rule

Field names follow Sigma where they map cleanly, so SigmaHQ Linux rules can be converted later.

```json
{
  "id": "PS04-SUDO-SETCAP",
  "title": "Sudo assignment of Linux file capabilities",
  "status": "stable",
  "category": "PS04",
  "level": "medium",
  "tags": ["attack.t1548.001"],
  "source": "log",
  "match": {
    "all": [
      { "field": "log.ident", "equals": ["sudo"] },
      { "field": "process.cmdline", "regex": ["\\bsetcap\\b"] }
    ]
  },
  "exceptions": [ { "users": ["ansible"] } ],
  "falsepositives": ["Configuration management granting cap_net_bind_service"],
  "response": "none"
}
```

| Field | Required | Notes |
|---|---|---|
| `id` | yes | `[A-Za-z0-9_.-]`, at most 128 bytes, unique across all loaded files. |
| `title` | yes | At most 256 bytes. Becomes `rule.title` on the event. |
| `category` | yes | `PS01`..`PS10`, see `pisentry categories`. |
| `level` | no | `info` (default), `low`, `medium`, `high`, `critical`. Becomes the event severity. |
| `source` | yes | Telemetry stream: `process` or `log`. `network`, `file` and `k3s` are rejected until a detector evaluates them. |
| `match` | yes | See below. |
| `mitre` / `tags` | no | Technique IDs (`T1548.001`). Sigma tags of the form `attack.t1548.001` are added to `mitre`. |
| `status` | no | `stable`, `test`, `experimental`, `deprecated`. |
| `description`, `author`, `references`, `falsepositives` | no | Documentation only. |
| `exceptions` | no | Up to 32. See below. |
| `response` | no | `none` (default), `kill_tree`, `quarantine`. Recorded only; no response actions run in v0.2. |

### Match

`all` conditions must all hold. If `any` is present, at least one of its conditions must also hold. A condition tests one field and is satisfied by any one of its patterns:

| Operator | Kind |
|---|---|
| `equals`, `contains`, `startswith`, `endswith` | Literal. Kept apart from regex so a literal prefilter can be added without a schema change. |
| `regex` | RE2 (Go `regexp`), no backtracking. At most 512 bytes. |
| `case_insensitive` | Applies to every pattern in the condition. |

Limits per rule: 32 conditions, 64 patterns. Exceeding a limit rejects the file; nothing is truncated.

### Fields and exception keys by source

A rule may only use the fields and exception keys its source fills. Anything else is a load error naming the rule and field, because it would load cleanly and never fire or never suppress.

| Source | What feeds it | Fields | Exception keys |
|---|---|---|---|
| `process` | The process scan | `process.pid`, `process.ppid`, `process.uid`, `process.comm`, `process.exe`, `process.cmdline`, `process.parent_comm` | `exe`, `exe_prefix`, `comm`, `parent_comm`, `uids`, `cmdline_contains` |
| `log` | sudo commands in the auth log | `log.ident` (always `sudo`), `log.msg`, `user.name`, `process.cmdline` (the command) | `users`, `cmdline_contains` |

Field names are [Event Schema v1](event-schema.md) names. `process.uid` and `process.parent_comm` cost extra `/proc` reads, which only happen for every process when some rule matches on them; otherwise they are read after a match, which is enough for exceptions.

`container_image`, `cidrs` and `paths` exceptions, and fields such as `source.ip`, `file.path` or `container.image`, will be accepted once a detector feeds network, file or k3s rules.

### Exceptions

An exception suppresses a match when every non-empty key in it matches. Several exceptions on a rule are ORed. An empty exception is rejected because it would silence the rule.

To add an exception to a built-in rule, copy the rule into `rules.d` with the same `id` and add `exceptions`. A rule in `rules.d` with a built-in `id` replaces the built-in rule. Two files in `rules.d` defining the same `id` is an error.

## Validating

```bash
pisentry check                       # built-in rules plus rules.dir from the config, as the agent loads them
pisentry check -rules /path/to/dir   # a file or directory on its own
```

Both exit 1 on the first error and name the file, rule and field. At startup, a broken `rules.d` is logged and the agent runs on the built-in rules rather than with none.

## Reloading

The running agent reloads `rules.d` without a restart:

- on SIGHUP (`sudo systemctl reload pisentry`, or `kill -HUP $(pidof pisentry)`), and
- when the contents of `rules.d` change, checked every `rules.reload_interval` (default `10s`, `0s` turns the watch off).

The directory is watched, not single files, and files are read through symlinks, so a Kubernetes ConfigMap update that swaps the `..data` symlink is picked up. A change has to be stable for 2 seconds before it is loaded, so copying several files is one reload.

The new set is compiled and validated in the background and swapped in atomically. If it fails, the previous set stays active, `pisentry_rules_reload_failures_total` goes up, the error is logged, and a High PS00 event names the file and field (the alert `PisentryRuleReloadFailed` fires on it). On success `pisentry_rules_loaded` and `pisentry_rules_last_reload_timestamp_seconds` change.

Rules and most catalog lists take effect on the next scan. `fim_watches` is read when the FIM detector starts, so a change to it needs a restart.

## Signed bundles

Rule updates between releases ship as a signed bundle. `pisentry update-patterns` installs one into `rules.d`. A signature alone does not stop a rollback: anyone who can serve an old, validly signed bundle could remove a newer rule. So the manifest also carries a version that only goes up and an expiry, and the agent enforces both.

A bundle is three kinds of file, with the same names on the download server, in `rules.d` and in a ConfigMap:

| File | Content |
|---|---|
| `bundle.manifest` | JSON manifest, below |
| `bundle.sig` | `{"key_id": "...", "signature": "<base64>"}`, an Ed25519 signature over the manifest bytes |
| `bundle-*.json` | Rule files, the same format as any file in `rules.d` |

```json
{
  "schema_version": 1,
  "version": 202611151200,
  "created": "2026-11-15T12:00:00Z",
  "expires": "2027-02-13T12:00:00Z",
  "min_agent_version": "v0.2.2",
  "files": [
    { "name": "bundle-ssh.json", "sha256": "1dbd4f8a...", "size": 165 }
  ]
}
```

The loader skips `bundle.manifest` and `bundle.sig` (they do not end in `.json`) and loads `bundle-*.json` like any other file. `bundle-*.json` names in `rules.d` belong to the updater: it removes the ones a new manifest no longer lists. Keep your own files under other names.

### pisentry update-patterns

```bash
sudo pisentry update-patterns                       # latest release, into rules.dir, then SIGHUP the agent
sudo pisentry update-patterns -url https://mirror.example/pisentry/ -rules /etc/pisentry/rules.d
pisentry update-patterns -rules ./rules.d -no-reload   # fill a directory for GitOps, no agent involved
```

It downloads `bundle.manifest` and `bundle.sig` from `-url` (HTTPS only, default `https://github.com/pisentry/pisentry/releases/latest/download/`), then checks, in this order:

1. the signature verifies with a key embedded in the binary, found by `key_id`,
2. `expires` is in the future,
3. `version` is higher than the version of the manifest in `rules.d` (the same version is "already installed", exit 0),
4. this agent is at least `min_agent_version` (development builds skip this),
5. every file matches its SHA-256 and size, and passes the same validation as `pisentry check`.

Only then does it write. Each file goes to a temporary dotfile, is synced and renamed into place, the manifest last. It then sends SIGHUP to any running `pisentry run`. Without the signal, the agent still sees the change within `rules.reload_interval`. Any failed check exits 1 and leaves `rules.d` as it was: an unsigned bundle, an unknown key, a bad signature, a tampered file, an older version or an expired manifest.

Run it from cron or a systemd timer, for example daily:

```
17 4 * * * root /usr/local/bin/pisentry update-patterns
```

### What the agent checks

On every load, at start and on each reload, the agent verifies a `bundle.manifest` in `rules.d`: the signature and the hash of every listed file. A failure is handled like any broken rule file. On a reload the previous set stays active and a High PS00 event names the problem. At start the agent runs on the built-in rules. An expired manifest still loads, because it was verified and dropping it would drop rules, but the agent logs a warning. `pisentry_rules_bundle_version` shows the version in the active set, or 0 when no bundle is installed.

`pisentry check` runs all of the update checks except the version comparison against a bundle in the checked directory, so a CI job can gate on it.

### Kubernetes

Do not run `update-patterns` in the pod. The pod's `rules.d` is a read-only ConfigMap mount, and an agent that fetches its own rules is one more thing that can be tampered with. Deliver the bundle through GitOps and let the agent only verify:

1. In CI or on a workstation, fetch and check the bundle into the repository:

   ```bash
   pisentry update-patterns -rules deploy/kubernetes/rules.d -no-reload
   pisentry check -rules deploy/kubernetes/rules.d
   ```

2. Commit the directory and generate a ConfigMap from it, for example with Kustomize:

   ```yaml
   configMapGenerator:
     - name: pisentry-rules
       namespace: pisentry
       files:
         - rules.d/bundle.manifest
         - rules.d/bundle.sig
         - rules.d/bundle-ssh.json
   ```

3. Mount it in the DaemonSet at its own path, not under the `/etc/pisentry` config mount, and point `rules.dir` (or `PISENTRY_RULES_DIR`) at it, for example `/etc/pisentry-rules`.

The agent verifies the signature and hashes on every reload, so a ConfigMap edited by hand, or half-synced, is rejected and the previous rules stay active. Review the version in the pull request: the agent cannot see a rollback in Git history. `pisentry check` fails on an expired manifest, so a pipeline that runs it catches a stale bundle.

### Keys

Two Ed25519 public keys are embedded in `internal/rules/bundle.go`: the current signing key and the next one. A key ID is the first 8 bytes of the SHA-256 of the public key, in hex, so it cannot point at the wrong key. A bundle signed with any other key is rejected.

To rotate: start signing with the next key (both are already trusted by every agent), then release a build that embeds the next key as current and a new next key. Agents that have not upgraded keep accepting bundles, because they trust the key now in use.

### One-time setup for maintainers

The release workflow signs `deploy/rules/packs/*.json` in the `rules-bundle` job and attaches the bundle to the GitHub release. The private key never leaves the `rules-signing` environment, and the job waits for a reviewer.

1. On a trusted machine, make the two keys:

   ```bash
   go run ./cmd/pisentry-bundle keygen -out current.key
   go run ./cmd/pisentry-bundle keygen -out next.key
   ```

   Each prints its public key and key ID.
2. Put both public keys into `trustedKeys` in `internal/rules/bundle.go` (current first) and merge that before the next release tag.
3. In the repository settings, under Environments, create `rules-signing`. Add yourself or another maintainer as a required reviewer, and limit deployment branches and tags to `v*` tags.
4. Add an environment secret `RULES_SIGNING_KEY` with the content of `current.key`.
5. Store `next.key` offline, for example in a password manager, and delete both key files from the machine.

The job verifies the signed bundle with the keys embedded in the release before attaching it. If the secret does not match an embedded key, the job fails and nothing is published. Bundles expire after 90 days. To refresh the latest release without new rules, re-run its `rules-bundle` job: the same files are signed with a newer version and a new expiry.

## Fixtures

Every built-in rule has recorded inputs under `internal/rules/testdata/rules/<rule-id>/`:

- `positive/*.json`: the rule must fire.
- `negative/*.json`: the rule must stay quiet. These come from normal activity on a Pi running k3s: apt upgrades, k3s restarts, backups, cron.

Each file is one normalized input with the same shape the detectors build:

```json
{
  "source": "log",
  "log_ident": "sudo",
  "log_msg": "    pi : TTY=pts/0 ; PWD=/home/pi ; USER=root ; COMMAND=/usr/sbin/setcap cap_setuid+ep /usr/bin/python3.13",
  "user": { "name": "pi" },
  "process": { "cmdline": "/usr/sbin/setcap cap_setuid+ep /usr/bin/python3.13" }
}
```

Input keys: `source`, `process` (`pid`, `ppid`, `uid`, `comm`, `exe`, `cmdline`), `parent_comm`, `user` (`name`), `log_ident`, `log_msg`. Unknown keys fail the test, so a typo cannot turn a positive fixture into a no-op.

`go test ./internal/rules/...` replays them with no root and no network. It fails when a rule lacks either kind, when a fixture directory names no rule, or when any fixture gives the wrong verdict. `make sim` stays the end-to-end check.
