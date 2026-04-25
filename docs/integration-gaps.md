# Integration gaps — what we'd want to patch before mass adoption

A walkthrough of the migration runbook against a typical
NSSM-wrapped service surfaced four small Recto-side gaps. None
block running the migration today, but each is worth a v0.2.x
patch before more services start moving onto Recto.

## 1. `migrate-from-nssm` treats every AppEnvironmentExtra entry as a secret

Today, every `KEY=value` pair in NSSM's `AppEnvironmentExtra`
becomes a Credential Manager entry under
`recto:<service>:<KEY>`. That's the right default for actual
secrets but wrong for non-secret operational env vars (e.g.
`PYTHONUNBUFFERED=1`, `DJANGO_DEBUG=0`, `LOG_LEVEL=info`).

After migration, the operator has to manually:

1. `recto credman delete <service> PYTHONUNBUFFERED`
2. Edit the generated YAML to add `spec.env: PYTHONUNBUFFERED: "1"`.
3. Restart the service.

**Fix.** Add a `--keep-as-env=NAME[,NAME...]` flag to
`recto migrate-from-nssm` that routes the named keys into
`spec.env` instead of CredMan. Plus a sensible default allow-list
for well-known non-secret prefixes (`PYTHON*`, `DJANGO_*`, `LOG_*`,
`*_DRY_RUN`, etc.).

Estimated impact: ~30 lines in `recto.cli._cmd_migrate_from_nssm`
and `recto._migrate.generate_service_yaml` plus a handful of
tests.

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
  internal endpoints (CF-Access service token, X-Verso-Token-style
  bespoke header, mTLS, whatever).

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

## 4. No CLI shortcut for "dump the event buffer"

When a service runs under NSSM, the launcher's stdout JSON events
go to whatever file NSSM has configured for `AppStdout`. To see
the in-memory event buffer (which is richer and structured), the
operator currently has to either:

- Browse to the admin UI (requires UI to be enabled + reachable).
- `curl http://127.0.0.1:5050/api/events` (requires UI enabled +
  knowledge of the bind port).

Neither works during an active incident if the admin UI is what
broke. A CLI fallback would help:

```
recto events <service>             # dump recent events as JSON
recto events <service> --kind child.exit --limit 20
```

**Fix.** Add a `recto.adminui.dump_events_via_socket()` helper
that hits the locally-bound admin UI from the same machine, plus
a `recto events` subcommand wrapping it. Falls back gracefully
when the admin UI isn't running ("admin UI not enabled or not
reachable; check `nssm get <service> AppStdout` for the JSON log
file").

## Out of scope for this list

- `recto apply` not reconciling healthz / comms / admin_ui:
  intentional. Those are launcher-runtime concerns, not NSSM-side
  config. The launcher reads the YAML at every spawn.
- NSSM `AppExit` exit-code policies not migrated: documented in
  the runbook; users on those features stay NSSM-only.
- `cloudflared` config for exposing the admin UI: out of scope
  for Recto entirely. Operators bring their own tunnel.

## Priority for v0.2.x

If we're picking one before standing up the first production
consumer, **gap 1** (non-secret env handling in migrate-from-nssm)
prevents the most operator confusion at migration time. **Gap 3**
(richer status payload) is the cheapest. **Gap 4** (CLI events
dump) helps incident response. **Gap 2** is a docs-only patch.

Easy to ship all four as a single v0.2.1 commit; total ~150 lines
of code + ~50 lines of tests.
