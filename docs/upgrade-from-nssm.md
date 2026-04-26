# Upgrading an NSSM service to Recto

This is the operational runbook for taking a service that already
runs under NSSM (with secrets in NSSM's `AppEnvironmentExtra` as
plaintext registry values) and wrapping it in Recto so the secrets
move into Credential Manager and the launcher gains healthz +
restart-policy + webhook + Job Object behavior.

The runbook below uses `myservice` throughout. Replace with your
actual NSSM service name.

## Prerequisites

- Recto installed: `pip install recto` (see [install.md](install.md)).
- Python 3.12+ on the host.
- NSSM on PATH. Verify: `nssm version`.
- The target NSSM service exists: `nssm status myservice` returns
  `SERVICE_RUNNING` or `SERVICE_STOPPED`.
- You have admin rights on the host (writing to Credential Manager
  + retargeting NSSM both require it).

## Step 1: Back up current NSSM config

NSSM stores config in the registry under
`HKLM\SYSTEM\CurrentControlSet\Services\myservice\Parameters`. A
plain `.reg` export gives you a one-step rollback path.

```powershell
reg export `
  "HKLM\SYSTEM\CurrentControlSet\Services\myservice\Parameters" `
  myservice-nssm-backup.reg /y
```

Stash that file somewhere outside the migration working directory.

## Step 2: Stop the service

```powershell
nssm stop myservice
```

The migration is non-destructive (CredWriteW upserts, NSSM `set` is
idempotent), but stopping first means the running child won't see
mid-migration env changes.

## Step 3: Dry-run the migration

```
recto migrate-from-nssm myservice --dry-run
```

This reads NSSM's current Application / AppParameters / AppDirectory /
AppEnvironmentExtra and prints a JSON plan describing what
`recto migrate-from-nssm` would do without `--dry-run`:

- For each `AppEnvironmentExtra` entry: install in Credential
  Manager under `recto:myservice:<KEY>`. Plan output masks values
  as `<redacted>` so you can paste it for review without leaking
  secrets.
- Generate a `myservice.service.yaml` in the current directory.
- Retarget NSSM `Application` to `python.exe` and `AppParameters` to
  `-m recto launch <abs-path>/myservice.service.yaml`.
- Reset NSSM `AppEnvironmentExtra` so plaintext secrets stop sitting
  in the registry.

Read the plan. Confirm:

- `current_environment_extra_count` matches what you expect.
- The list of `secrets_to_install` covers every key your service
  reads from env at startup (especially API keys, tokens, signing
  keys, etc.).
- `new_app_path` is the python.exe you actually want the service
  to use. Pass `--python-exe C:\Python312\python.exe` to pin a
  specific install rather than relying on PATH resolution.

## Step 4: Apply the migration

```
recto migrate-from-nssm myservice
```

When this returns successfully, NSSM has been retargeted at Recto
and Credential Manager holds the secrets. The generated YAML lives
at `myservice.service.yaml` in your current directory (use
`--yaml-out path/to/myservice.service.yaml` to put it elsewhere --
typically inside the consuming repo's tree so the YAML is reviewable
in PRs).

## Step 5: Verify the secrets landed

```
recto credman list myservice
```

Should print one name per line, sorted, matching the keys that were
in NSSM's `AppEnvironmentExtra`. Values are never displayed -- this
is the inventory view.

If you need to add a secret that wasn't in the NSSM env (e.g. you're
adding a webhook token that the new YAML's `comms:` block needs):

```
recto credman set myservice WEBHOOK_TOKEN
# prompts for the value via getpass; the value never appears on the
# command line and is not echoed
```

## Step 6: Edit the generated YAML

`recto migrate-from-nssm` produces a minimum viable
`myservice.service.yaml` -- it covers `metadata`, `spec.exec`,
`args`, `working_dir`, `secrets`, and a default `restart` policy.
Everything else (healthz, comms, resource_limits, admin_ui,
telemetry) is left out.

Open the YAML and add the sections you want. See
[examples/sample.service.yaml](../examples/sample.service.yaml) for
the full reference. Common additions:

- **healthz** -- if your service has a `/healthz` (or equivalent)
  endpoint, add an `http` probe. If it just listens on a port, use
  `tcp`. If you have a bespoke check command, use `exec`.
- **comms** -- if you want webhook notifications on restart/health
  failure events, configure one or more webhook sinks. Headers can
  reference secrets via `${env:KEY_NAME}` (the launcher resolves
  the secret from Credential Manager into the child env at spawn
  time, and the comms dispatcher uses that env for header
  interpolation).
- **resource_limits** -- if the child should die if it leaks past
  N MB or hogs the CPU.
- **admin_ui** -- if you want a local web UI showing recent
  lifecycle events. Bind defaults to `127.0.0.1:5050`; expose
  externally via Cloudflare Tunnel + CF Access (or any reverse
  proxy you trust) -- Recto trusts every connection that reaches
  it, auth is the proxy's job.

## Step 7: Reconcile NSSM to match the YAML

After every YAML edit (now and forever), run:

```
recto apply myservice.service.yaml --dry-run
```

Inspect the diff. The plan output lists every NSSM scalar field
that would change (Application, AppParameters, AppDirectory,
DisplayName, Description) plus a `! AppEnvironmentExtra: will be
cleared` line if there are still leftovers. Then:

```
recto apply myservice.service.yaml --yes
```

`--yes` skips the y/N confirmation prompt; omit it for interactive
review.

## Step 8: Start the service

```powershell
nssm start myservice
```

NSSM now invokes `python.exe -m recto launch path\to\myservice.service.yaml`,
which:

1. Loads the YAML.
2. Resolves declared secrets from Credential Manager.
3. Composes the child env (`os.environ` -> `spec.env` -> resolved
   secrets, last wins).
4. Spawns the child via `subprocess.Popen` with that env.
5. (If `admin_ui.enabled`) binds the admin server.
6. (If `healthz.enabled`) starts the probe loop in a daemon thread.
7. (If `resource_limits` set) attaches the child to a Win32 Job
   Object with KILL_ON_JOB_CLOSE.
8. (If `telemetry.enabled` AND `[otel]` extra installed) opens an
   OTLP span for the run.
9. Waits for the child to exit OR healthz to signal unhealthy. On
   probe failure, SIGTERMs the child and lets the restart policy
   decide whether to respawn.
10. Emits structured JSON events to stdout (visible via
    `nssm get myservice AppStdout` log file) plus any configured
    webhook sinks plus the admin UI's in-memory event buffer plus
    the OTel span.

## Step 9: Verify

```
recto status myservice          # exit 0 if SERVICE_RUNNING
```

Plus, if admin_ui is enabled, browse to
<http://127.0.0.1:5050> (or the Cloudflare-tunneled hostname). You
should see:

- **Status tab**: service name, healthz/restart shape from the
  YAML, launcher uptime.
- **Events tab**: at least one `child.spawn` event from this run.
- **Restart History tab**: empty unless the service has actually
  restarted yet -- expected.

## Failure modes

### "NSSM service `myservice` not found"

The NSSM service doesn't exist yet. `recto migrate-from-nssm` only
migrates EXISTING services; it doesn't register new ones. Run
`nssm install myservice` first.

### "secret_name 'KEY_X' is required but not found in CredMan"

A secret declared in your YAML's `secrets:` block isn't installed.
Run `recto credman set myservice KEY_X` to install it.

### Service starts but healthz immediately trips

The probe is running but the child isn't responding the way the
probe expects. Check the URL/host/port/command in `spec.healthz`,
make sure `restart_grace_seconds` is generous enough for the
child's startup time, and confirm `failure_threshold` matches your
tolerance.

### Admin UI doesn't bind

If port 5050 (or whatever you configured) is already in use, you'll
see an `adminui.bind_failed` event in the launcher's stdout JSON.
The supervised child still runs; only the UI is skipped. Pick a
different port via `spec.admin_ui.bind`.

## Rollback

If anything goes sideways and you need to revert to the original
NSSM config:

```powershell
nssm stop myservice
reg import myservice-nssm-backup.reg
nssm start myservice
```

Credential Manager entries created during the migration remain
(they're harmless if no consumer reads them); clean them up
explicitly if needed:

```
recto credman list myservice           # see what's there
recto credman delete myservice KEY_X
```

## Where the YAML lives

A few conventions:

- **Inside the consumer's repo, alongside the code that runs.** The
  YAML is part of the service's deployment surface area; it should
  be reviewable in PRs and version-controlled. Common path:
  `<repo>/<servicename>.service.yaml`.
- **Pointing NSSM at a stable absolute path.** NSSM's
  `AppParameters` will be set by `recto migrate-from-nssm` to
  `-m recto launch <abs-path-to-yaml>`. If you later move the YAML,
  re-run `recto migrate-from-nssm --yaml-out new/path` (or just
  `nssm set myservice AppParameters "-m recto launch <newpath>"`).

## What doesn't migrate automatically

Things `recto migrate-from-nssm` does NOT pull from NSSM, by
design:

- `AppExit` exit-code policies. NSSM's exit-code-conditional restart
  policies have no equivalent in Recto's `spec.restart`; if you
  rely on them, stay on NSSM-only or adjust your child to use exit
  codes Recto's policy understands.
- `AppRestartDelay`. Recto's `spec.restart.initial_delay_seconds`
  + backoff is the equivalent; tune them in the YAML.
- `AppRotate*` log rotation settings. NSSM still owns stdout/stderr
  redirection (`AppStdout` / `AppStderr`) and rotation; Recto's
  output goes through whatever NSSM is already configured for.
- `DependOnService`. NSSM service-dependency chains stay in NSSM;
  unaffected.

If you discover a NSSM feature you rely on that didn't migrate,
file an issue.
