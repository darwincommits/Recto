# Installing Recto

## Requirements

- **Python 3.12 or newer.** Recto uses `datetime.UTC`, `slots=True`
  dataclasses, and other 3.12+ idioms. On Windows, the Microsoft
  Store install of Python 3.12 works -- note that it registers as
  `python3.12` directly on PATH, NOT under the `py -3.12` launcher.
- **Windows 10 / 11 or Server 2019+** for the production
  Credential-Manager + Job-Object backends. Cross-platform support
  for the substrate is on the v0.3 ROADMAP.
- **NSSM on PATH** (Windows). Recto v0.2 wraps NSSM as the service
  registrar; `recto status` and `recto migrate-from-nssm` shell
  out to `nssm.exe`. Get it from <https://nssm.cc/>.

## Install

```
pip install recto
```

That brings in the launcher path with stdlib-only runtime
dependencies (PyYAML is the one external requirement). To enable
OpenTelemetry traces, add the `[otel]` extra:

```
pip install recto[otel]
```

For development:

```
git clone https://github.com/<your-fork>/Recto
cd Recto
pip install -e ".[dev]"
pytest
```

## Verify

```
recto --version
python -m recto --version
```

Both should print the same version string. Recto exposes both a
console-script entry (`recto`) and a `python -m recto` entry; they
target the same `recto.cli:main`.

## Smoke test

A 30-second smoke that doesn't need NSSM or Credential Manager:

```yaml
# smoke.service.yaml
apiVersion: recto/v1
kind: Service
metadata:
  name: smoke
spec:
  exec: python.exe
  args: ["-c", "import time; print('hello from smoke'); time.sleep(2)"]
  admin_ui:
    enabled: true
    bind: 127.0.0.1:5050
```

Run it once:

```
python -m recto launch smoke.service.yaml --once
```

While the child sleeps for 2 seconds, the admin UI is live at
<http://127.0.0.1:5050>. You'll see the `child.spawn` event in the
Events tab. After exit, the launcher returns the child's exit code
(0).

## What ships

Recto v0.2 includes:

- `recto.launcher` -- supervises a child process: composes env from
  YAML + secrets, spawns, runs healthz probe + restart loop, dispatches
  webhook events.
- `recto.healthz` -- HTTP / TCP / exec liveness probes.
- `recto.restart` -- exponential / linear / constant backoff with
  max-attempts cap.
- `recto.comms` -- webhook event dispatcher with template
  interpolation for headers + body.
- `recto.joblimit` -- Win32 Job Object resource limits
  (memory_mb / cpu_percent / process_count) with KILL_ON_JOB_CLOSE.
- `recto.telemetry` -- optional OpenTelemetry traces (one span per
  run() with lifecycle events as span events).
- `recto.adminui` -- read-only HTTP admin server with three JSON
  endpoints + an embedded HTML index.
- `recto.secrets.credman` -- Windows Credential Manager backend.
- `recto.secrets.env` -- pass-through env-var backend (dev/test).
- `recto.cli` -- `launch`, `credman set/list/delete`, `status`,
  `migrate-from-nssm`, `apply` subcommands.

## Next

- **Migrating an existing NSSM service to Recto:** see
  [docs/upgrade-from-nssm.md](upgrade-from-nssm.md).
- **YAML reference:** see [examples/sample.service.yaml](../examples/sample.service.yaml).
- **Architecture:** see [ARCHITECTURE.md](../ARCHITECTURE.md).
