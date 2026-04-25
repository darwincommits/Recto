# Recto — AI memory

Project memory for AI assistants contributing to Recto. Cross-cutting rules,
architectural conventions, and Gotchas the codebase has accumulated. This file
is committed and public; anything machine-specific, identity-specific, or
operator-specific lives in `.claude/local.md` (gitignored).

## Conversation startup ritual

Before responding to the first message of a new conversation, load these in
order:

1. **`.claude/local.md`** if it exists — operator-specific overrides
   (machine identification, git author identity, infrastructure notes, etc.).
   This file is gitignored; don't be alarmed if it's absent on a fresh clone.
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
   NSSM, not the other way around. NSSM's `AppPath` points at `python -m
   recto launch service.yaml`. v0.2+ may absorb the registration
   responsibility natively, but NEVER without a documented migration path.
6. **The plugin seam (SecretSource ABC) is the public API contract.** Adding
   a new backend MUST NOT require changes to `recto.launcher` or any
   consumer's service.yaml beyond the `source:` selector. New backends
   declare themselves; the launcher stays generic.
7. **AI-driven commits author as `Darwin`.** Never push under a generic AI
   identity. The git config (name + email) for AI-driven commits lives in
   `.claude/local.md`; load it before committing.
8. **No internal-detail leaks in committed files.** Operator-specific
   hostnames, usernames, internal domain names, sibling-repo names, specific
   consumer apps, and PAT or service-token names belong only in
   `.claude/local.md`. The committed tree should read like a generic OSS
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
├── .claude/                           gitignored — operator-specific memory
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
  lesson (sandbox quirks, the operator's tooling) → `.claude/local.md`
  Gotchas.
- **New convention or rule.** OSS-relevant rule → Hard rules above.
  Operator-specific workflow rule → `.claude/local.md` Workflow rules.
- **Architectural decision** → ARCHITECTURE.md (with date stamp).
- **Feature shipped** → CHANGELOG.md.
- **Future work item** → ROADMAP.md.
- **Identity / infrastructure detail** (machine names, PATs, domain names,
  consumer app names, git author identity, hosting topology) → ALWAYS
  `.claude/local.md`, never the public tree.

When the operator says **"I'm starting a new conversation next"** — that's
the cue to run a memory consolidation pass: scan for duplication between
this file and ARCHITECTURE.md / ROADMAP.md / `.claude/local.md`, retire
stale TODOs, merge overlapping gotchas. Especially: scan for any
operator-specific detail that crept into a public file and move it.

## Gotchas index (public)

Generic technical gotchas only. Operator-environment-specific gotchas live
in `.claude/local.md`.

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
