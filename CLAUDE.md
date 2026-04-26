# Recto — AI memory

Project memory for AI assistants contributing to Recto. Cross-cutting rules,
architectural conventions, and Gotchas the codebase has accumulated. This file
is committed and public; anything machine-specific, identity-specific, or
operator-specific lives in `%USERPROFILE%\private\local.md` (outside any
repo, manually synced across machines — see that file for the sync recipe).

## Conversation startup ritual

Before responding to the first message of a new conversation, load these in
order:

1. **`%USERPROFILE%\private\local.md`** if it exists — operator-specific
   overrides (machine identification, git author identity, infrastructure
   notes, etc.). The file lives at user-home level, OUTSIDE any repo, so
   it's shared across all sibling repos (Recto and any others) on the same
   machine without per-repo duplication. **Cowork mount hint**: this path
   lives at user-home, not inside any per-project mount; in a fresh
   Cowork session, AI must call `request_cowork_directory` with the path
   `%USERPROFILE%\private` first so the operator can approve mounting it,
   THEN Read the file. Don't be alarmed if it's absent on a fresh clone
   or on a new machine. (Path history: started at `.claude/local.md`
   inside Recto; moved to `Recto/private/local.md` on 2026-04-26 morning
   because Cowork's sandbox blocks AI Write/Edit on `.claude/` paths;
   promoted to `%USERPROFILE%\private\local.md` later the same day so
   all sibling repos share one canonical file. The in-repo `private/` dir
   still exists as a scratch space for transient commit-message tempfiles,
   but no longer holds long-term memory.)
2. **This file** — you're here.
3. **`README.md`** — public pitch, status, license.
4. **`ARCHITECTURE.md`** — design doc covering YAML schema, pluggable
   secret-source backends, NSSM relationship, threat model.
5. **`ROADMAP.md`** — phasing: what's shipped, what's next, what's deferred.

Don't narrate the read-pass back to the user.

## Hard rules (non-negotiable)

1. **Backward compatibility on the YAML schema.** `apiVersion: recto/v1` is
   locked at v0.1. Additive only — no breaking renames, no field removals.
   Deprecation periods of two minor versions before any removal. If a v2
   schema is needed, it's a separate `apiVersion: recto/v2` that lives
   alongside v1, not in place of it.
2. **Secrets never logged, never serialized, never echoed in stack traces.**
   When a secret value passes through Recto, it's a `bytes` or `str`
   immediately consumed; never stored in a longer-lived object than necessary.
   `SecretMaterial.__repr__` returns `"<redacted>"`. Any new code path that
   handles secret values must follow the same convention.
3. **Public-domain spirit, Apache 2.0 license.** No commercial-only features
   in `recto-core`. Phase 4 hardware-enclave backends may be a separate paid
   offering, but the substrate stays free and open.
4. **Single-file-runnable for the launcher path.** `python -m recto launch
   <yaml>` works without any extra setup beyond `pip install recto`. No
   server-side daemon, no central registry, no "first set up postgres."
5. **NSSM stays the Windows-service registrar in v0.1.** Recto is wrapped BY
   NSSM, not the other way around. NSSM's `Application` parameter points at
   `python -m recto launch service.yaml`. v0.2+ may absorb the registration
   responsibility natively, but NEVER without a documented migration path.
6. **The plugin seam (SecretSource ABC) is the public API contract.** Adding
   a new backend MUST NOT require changes to `recto.launcher` or any
   consumer's service.yaml beyond the `source:` selector. New backends
   declare themselves; the launcher stays generic.
7. **AI-driven commits author as `Darwin`.** Never push under a generic AI
   identity. The git config (name + email) for AI-driven commits lives in
   `%USERPROFILE%\private\local.md`; load it before committing.
8. **No internal-detail leaks in committed files.** Operator-specific
   hostnames, usernames, internal domain names, sibling-repo names, specific
   consumer apps, and PAT or service-token names belong only in
   `%USERPROFILE%\private\local.md`. The committed tree should read like a generic OSS
   project a stranger could fork without learning the operator's setup.

## Repo layout (matches what's on disk)

```
Recto/
├── README.md
├── LICENSE                            Apache 2.0
├── CLAUDE.md                          this file (public AI memory)
├── ARCHITECTURE.md                    design doc
├── ROADMAP.md                         phased shipping plan
├── CHANGELOG.md                       per-release log
├── .gitignore
├── private/                           gitignored — scratch dir for commit-msg tempfiles (long-term memory now lives at %USERPROFILE%\private\local.md)
├── .github/workflows/                 CI + deploy (later)
├── pyproject.toml                     Python 3.12+, Apache-2.0, deps
├── recto/                             the package
│   ├── __init__.py
│   ├── __main__.py                    python -m recto entry point
│   ├── cli.py                         argparse-based CLI
│   ├── launcher.py                    wrapped-service host process
│   ├── config.py                      YAML schema + validation
│   ├── healthz.py                     HTTP probe loop
│   ├── restart.py                     backoff + max_attempts policy
│   ├── comms.py                       webhook event dispatch
│   ├── nssm.py                        NSSM imperative-state read/reconcile (v0.2)
│   ├── joblimit.py                    Win32 Job Object resource limits (v0.2)
│   ├── otel.py                        OpenTelemetry traces (v0.2)
│   ├── adminui/                       v0.2 web UI
│   └── secrets/
│       ├── base.py                    SecretSource ABC, SecretMaterial sealed type
│       ├── env.py                     plain env-var passthrough
│       ├── credman.py                 Windows Credential Manager (v0.1)
│       ├── keychain.py                macOS Keychain (v0.3)
│       ├── secretsvc.py               Linux Secret Service (v0.3)
│       ├── aws.py                     AWS Secrets Manager (v0.3)
│       └── vault.py                   HashiCorp Vault (v0.3)
├── tests/
├── examples/                          example service.yaml files
└── docs/                              install, service-config, secrets, threat-model
```

## "Update your IM" convention

When the operator says **"Update your IM"**, add the lesson to the most-scoped
place that keeps it discoverable and respects the public/private split:

- **Hard-won debugging lesson.** Generic technical lesson → Gotchas section
  below + the most-relevant module's docstring. Operator-environment-specific
  lesson (sandbox quirks, the operator's tooling) → `%USERPROFILE%\private\local.md`
  Gotchas.
- **New convention or rule.** OSS-relevant rule → Hard rules above.
  Operator-specific workflow rule → `%USERPROFILE%\private\local.md` Workflow rules.
- **Architectural decision** → ARCHITECTURE.md (with date stamp).
- **Feature shipped** → CHANGELOG.md.
- **Future work item** → ROADMAP.md.
- **Identity / infrastructure detail** (machine names, PATs, domain names,
  consumer app names, git author identity, hosting topology) → ALWAYS
  `%USERPROFILE%\private\local.md`, never the public tree.

When the operator says **"I'm starting a new conversation next"** — that's
the cue to run a memory consolidation pass: scan for duplication between
this file and ARCHITECTURE.md / ROADMAP.md / `%USERPROFILE%\private\local.md`, retire
stale TODOs, merge overlapping gotchas. Especially: scan for any
operator-specific detail that crept into a public file and move it.

## Gotchas index (public)

Generic technical gotchas only. Operator-environment-specific gotchas live
in `%USERPROFILE%\private\local.md`.

- **Force-push doesn't overwrite when local is a fast-forward descendant
  of remote.** `git push --force` only rewrites remote history if local
  has a different ancestry. If local main is a clean descendant of
  origin/main (you cloned, made one commit on top), `--force` is a no-op
  beyond what a regular push would do — the remote history grows by your
  appended commit; nothing is overwritten. To truly REWRITE history (e.g.
  scrub leak terms from earlier commits, replace an auto-generated
  Initial commit), build an orphan branch:
  ```
  git checkout --orphan fresh-main
  git add .
  git commit -m "..."
  git branch -D main
  git branch -m fresh-main main
  git push --force origin main
  ```
  The orphan has no parent, so local and remote share zero ancestry, so
  `--force` actually overwrites. The push output should include
  `(forced update)`.
- **`datetime.UTC` requires Python 3.11+.** Recto's `pyproject.toml` targets
  3.12, so `from datetime import UTC` is fine in production. If a contributor's
  test environment is on 3.10 (some CI base images, some sandboxes), the
  ruff `UP017` auto-fix that lands `datetime.UTC` will fail to import there.
  Either run on 3.12 or revert with a `# noqa: UP017` on the `timezone.utc`
  form. This is a contributor-environment issue, not a portability concern —
  production targets 3.12.
- **NSSM's executable-path parameter is `Application`, NOT `AppPath`.** The
  "App" prefix is non-uniform across NSSM's parameter family — `AppParameters`,
  `AppDirectory`, `AppEnvironmentExtra`, `AppExit`, `AppStdout`, `AppRotate*`
  all carry the prefix, but the foundational parameter naming the executable
  is plain `Application`. NSSM rejects `nssm get/set <svc> AppPath` with
  `Invalid parameter "AppPath"`. The `nssm dump <svc>` output is canonical;
  any code using NSSM parameter names should be cross-checked against a real
  `nssm dump` rather than against the author's intuition about the naming
  pattern. Test fixtures must match real NSSM parameter names — using a
  fictitious name for a "stand-in" makes the test pass against fiction
  rather than against the production behavior. (Caught during first-consumer
  migration round 1 when `recto migrate-from-nssm <service> --dry-run`
  bombed at the read step; fixed by global string-rename `"AppPath"` →
  `"Application"` in `recto/nssm.py`, `recto/cli.py`, `recto/reconcile.py`,
  and matching test fixtures. Python attribute name `app_path` and
  migration-plan key `new_app_path` keep their existing names — they're
  our abstraction over NSSM's name, and clearer for operators reading the
  dry-run plan.)
- **Cowork sandbox FUSE mount lags edits made via Read/Write/Edit tools.**
  After a sequence of file-tool edits, `bash` may see truncated files
  (cut off mid-line, possibly null-padded), report wrong line counts, and
  Python `ast.parse()` chokes with `SyntaxError: unterminated string
  literal` or `source code string cannot contain null bytes` even though
  the actual Windows-side file is healthy. Symptom: file tools' Read shows
  the file is fine; `bash cat`/`wc -l`/`python -c 'ast.parse(...)'` all
  agree the file is broken. The Windows-side file is the truth. Workaround
  for "I need to run pytest after edits": clone fresh in `/tmp` via
  `git clone https://github.com/.../`, apply patches via `sed`/Python in
  the fresh tree, run pytest there. Don't try to make the bash mount
  agree with the tool-edited tree — sandbox-environment artifact, not a
  real bug. Worth its own entry here because it blocks `pytest` after
  large edit sequences.
- **`recto apply` defaults `Application` to bare `python.exe` if
  `--python-exe` isn't passed.** When applying a YAML against a
  Recto-managed service, `recto apply`'s diff proposes changing NSSM's
  `Application` from a fully-qualified path (e.g. `C:\Python314\python.exe`)
  to just `python.exe`. That breaks service start under any service-account
  context whose PATH doesn't include the right Python. Workaround: pass
  `--python-exe <abs-path>` to `recto apply`. Suggested fix: default to
  whatever the migrator originally set, or to `sys.executable` of the
  running interpreter, or emit a clear "must pass --python-exe" error.
  Caught during second-consumer migration 2026-04-26.
- **`recto credman list <service>` returns empty for dpapi-machine
  entries.** The `credman list` subcommand only enumerates the per-user
  `credman` backend; dpapi-machine secrets at
  `C:\ProgramData\recto\<service>\*.dpapi` aren't surfaced. Operators
  fall back to filesystem listing as canonical proof of installation.
  Suggested fix: rename to `recto secrets list <service>` and walk all
  backends, OR add `recto dpapi-machine list <service>` as a sibling
  subcommand. Caught during second-consumer migration 2026-04-26.
- **`recto apply` collapses `metadata.description` into both NSSM
  `DisplayName` AND `Description`.** The YAML schema currently has a
  single `description` field; `recto apply` writes that string into both
  registry parameters. Functional but lossy vs the distinct values that
  are typical to set during initial NSSM install (DisplayName: short
  title; Description: longer prose). Suggested fix: add
  `metadata.display_name` to the YAML schema as an optional field; when
  present, write to NSSM `DisplayName`; when absent, fall back to current
  behavior. Caught during second-consumer migration 2026-04-26.
- **`migrate-from-nssm` silently skips `--keep-as-env` entries that
  aren't in the source env.** When `--keep-as-env=KEY1,KEY2,KEY3` is
  passed but `KEY3` isn't in NSSM's `AppEnvironmentExtra`, the migrator
  skips KEY3 without warning. Confused a runbook step that predicted
  "should print 15 lines" when the actual env had 14 (one declared
  keep-as-env name didn't exist in the source). Suggested fix: emit a
  warning like `recto migrate-from-nssm: --keep-as-env entry '<NAME>'
  not found in source env (skipping)` so operators know the partition
  came out smaller than declared. Caught during second-consumer
  migration 2026-04-26.

## Adoption history (non-identifying)

- **First production consumer migrated 2026-04-26**, after 7 rounds of
  bug fixes + iteration that hardened the launcher, the dpapi-machine
  backend, and `migrate-from-nssm` against real-world NSSM installs.
  Each round surfaced one or more bugs that landed in v0.2.x; details
  in CHANGELOG.md. The dpapi-machine backend (vs the per-user `credman`
  default) was forced by round 6 bug 5b — services running under
  `LocalSystem` couldn't read CredMan entries written by an admin user;
  machine-bound DPAPI sidesteps the issue.
- **Second production consumer migrated 2026-04-26 (same day).**
  Migration went 1-shot through every step — every fix earned during
  the first-consumer rounds applied cleanly. Surfaced the four
  observations now captured in the gotchas index above (CLI UX papercuts,
  not architectural). Confirms the v0.2.2 substrate is stable enough
  for additional consumers without per-consumer bug archaeology.
- **First full secret rotation against both consumers 2026-04-26
  (same day).** Operator-driven rotation pass through 10 dpapi-machine
  secret entries across the two consumers, plus the staging-server
  host password that NSSM `ObjectName` depends on. Proved the
  encrypt-via-`Read-Host -AsSecureString` → write `.dpapi` → restart
  service → Recto launcher decrypts at child-spawn → child env-var
  receives plaintext round-trip works for every secret type the
  substrate handles. Both consumers smoke-tested green within seconds
  of post-rotation restart. Two papercuts surfaced — both consumer-
  side, not Recto-internal: (a) consumer rotator scripts didn't
  `Add-Type -AssemblyName System.Security` for
  `[System.Security.Cryptography.ProtectedData]` on Windows PowerShell
  5.1 — irrelevant to Recto itself since the launcher's DPAPI
  implementation is Python ctypes against `crypt32.dll`, not .NET.
  (b) Consumer runbook initially mis-labeled which client owned a
  specific admin-secret name — also irrelevant to Recto. No Recto-
  side bugs. The substrate handled every rotation cleanly without a
  single launcher restart loop or decrypt failure across 10 rotated
  secrets + 2 service restarts.
