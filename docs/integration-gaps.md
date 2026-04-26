# Integration gaps — what we'd want to patch before mass adoption

A walkthrough of the migration runbook against a typical
NSSM-wrapped service surfaced four small Recto-side gaps. Two
have shipped (1, 4); two remain (2, 3). None block running the
migration today, but each is worth a v0.2.x patch before more
services start moving onto Recto.

## 1. `migrate-from-nssm` treats every AppEnvironmentExtra entry as a secret — **shipped**

Originally: every `KEY=value` pair in NSSM's `AppEnvironmentExtra`
became a Credential Manager entry under `recto:<service>:<KEY>`.
That was the right default for actual secrets but wrong for
non-secret operational env vars (e.g. `PYTHONUNBUFFERED=1`,
`DJANGO_DEBUG=0`, `LOG_LEVEL=info`).

**Shipped in v0.2.2:** `recto migrate-from-nssm
--keep-as-env=NAME[,NAME...]` routes the named keys into the
generated YAML's `spec.env:` block instead of Credential Manager.
The default (no flag) keeps v0.1 behavior — every entry treated as
a secret. Implementation in `recto._migrate.partition_env_entries()`
and `recto._migrate.generate_service_yaml()` (emits a `spec.env:`
block when plain-env entries are present); CLI wiring in
`recto.cli._cmd_migrate_from_nssm`. 10 new tests in
`tests/test_cli.py` covering the partition logic, the spec.env
emission, and the round-trip through `load_config`. The default
allow-list for well-known non-secret prefixes (`PYTHON*`,
`DJANGO_*`, `LOG_*`, etc.) was deferred — `--keep-as-env` is
explicit-only, which keeps the behavior unsurprising.

## 2. Consumer services need an inbound endpoint for lifecycle events

Recto's `comms` dispatcher POSTs `child.spawn` / `child.exit` /
`restart.*` events to whatever URL the YAML names. Most consumer
services don't already have a "receive Recto events" endpoint;
they'll need to add one.

This is consumer-side, not Recto-side, but worth documenting a
convention so every service does it the same way. Suggestion:

- `POST /api/recto/events` on the consumer.
- Body is the full JSON record Recto emits to stdout (the same
  shape that goes into the admin UI's event buffer).
- Auth via the same headers operators use for their other
  internal endpoints (CF-Access service token, a bespoke
  X-Auth-Token-style header, mTLS, whatever).

**Fix.** Document the convention in `docs/comms-receiver.md` with
a reference handler implementation in Python stdlib + a sample
nginx / Caddy snippet for putting it behind auth.

## 3. Admin UI `/api/status` shows launcher uptime, not service-state

`uptime_seconds` in the status payload is "how long has the
EventBuffer existed" -- effectively, how long the launcher
process has been alive. That's useful but less so than:

- `restart_count` (how many times the child has respawned during
  this run).
- `last_spawn_ts` (when did the most recent child start).
- `last_exit_returncode` (what did the previous child exit with;
  null if no exit yet).
- `last_healthz_signaled_ts` (when did the probe last trip; null
  if never).

The EventBuffer already has the data -- these are derived
properties over the existing event stream.

**Fix.** Add the four fields to `_ServerState.status_payload()`,
extend the embedded HTML index to render them in the Status tab.
~20 lines of code, ~5 of tests.

## 4. No CLI shortcut for "dump the event buffer" — **shipped**

When a service runs under NSSM, the launcher's stdout JSON events
go to whatever file NSSM has configured for `AppStdout`. To see
the in-memory event buffer (which is richer and structured),
operators originally had only:

- Browsing to the admin UI (requires UI to be enabled + reachable).
- `curl http://127.0.0.1:5050/api/events` (requires UI enabled +
  knowledge of the bind port).

Neither works during an active incident if the admin UI is what
broke (or if you're SSH'd in without a browser).

**Shipped in v0.2.2:** `recto events <yaml> [--kind K] [--limit N]
[--restart-history]` reads the YAML to find `spec.admin_ui.bind`,
GETs `http://<bind>/api/events` (or `/api/restart-history`), and
prints the JSON. Multi-kind filter via comma-separated `--kind`.
Falls back gracefully when `spec.admin_ui.enabled` is false or the
server isn't reachable, pointing the operator at NSSM's AppStdout
log file. CLI wiring in `recto.cli._cmd_events` with an injected
`fetch_url` seam for tests. 10 new tests in `tests/test_cli.py`.

## Out of scope for this list

- `recto apply` not reconciling healthz / comms / admin_ui:
  intentional. Those are launcher-runtime concerns, not NSSM-side
  config. The launcher reads the YAML at every spawn.
- NSSM `AppExit` exit-code policies not migrated: documented in
  the runbook; users on those features stay NSSM-only.
- `cloudflared` config for exposing the admin UI: out of scope
  for Recto entirely. Operators bring their own tunnel.

## Priority for v0.2.x

Gaps 1 and 4 shipped in v0.2.2 (see entries above). Remaining work:

- **Gap 2** (consumer-side `/api/recto/events` convention) is
  docs-only. Worth landing once we have a second consumer that
  needs to receive events; until then the example reference
  implementation can live with the consumer that adopts it first
  rather than in Recto's docs.
- **Gap 3** (richer admin UI status payload) is cheap (~20 lines)
  and high-value for an operator opening the dashboard. Land it
  alongside any other admin UI work.
