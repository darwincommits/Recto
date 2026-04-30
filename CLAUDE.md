# Recto — AI memory

Project memory for AI assistants contributing to Recto. Cross-cutting rules,
architectural conventions, and Gotchas the codebase has accumulated. This file
is committed and public; anything machine-specific, identity-specific, or
operator-specific lives in `%USERPROFILE%\private\local.md` (outside any
repo, manually synced across machines — see that file for the sync recipe).

## Conversation startup ritual

Before responding to the first message of a new conversation, an AI
assistant should silently load these in order. Don't narrate the
read-pass back to the user.

1. **`local.md` — operator-specific overrides** (machine identification,
   git author identity, infrastructure notes, etc.). Look in these
   locations in order; first hit wins:
     - `%USERPROFILE%\private\local.md` (Windows, when localmd is
       cloned to `~/private`)
     - `$HOME/private/local.md` (macOS / Linux, same convention)
     - `$HOME/Documents/GitHub/localmd/local.md` (macOS / Windows
       when GitHub Desktop's default clone path is used — repo at
       `https://github.com/erikcheatham/localmd`)
     - `$HOME/localmd/local.md` (CLI default `git clone` location)

   The file is the operator's private memo. In a fresh Cowork-style
   session, AI may need to call `request_cowork_directory` to be
   granted access to whichever directory holds it before reading.
   Don't be alarmed if the file is absent — it's per-operator and
   won't exist on a fresh public clone.
2. **This file** — you're here.
3. **`README.md`** — public pitch, status, license.
4. **`ARCHITECTURE.md`** — design doc covering YAML schema, pluggable
   secret-source backends, NSSM relationship, threat model.
5. **`ROADMAP.md`** — phasing: what's shipped, what's next, what's deferred.
6. **`docs/macos-setup.md`** if the operator is on a the macOS host host running
   the MAUI Blazor phone app or a self-hosted GitHub Actions
   runner — covers iOS device deploy, the Apple Developer Program
   ceremony, the macOS pytest-on-self-hosted-runner workflow, and
   recovery patterns for runner self-update corruption.

If the operator's `local.md` defines a multi-machine role-gate or a
canonical fresh-conversation trigger phrase, follow what's in that
file. The substrate is generic; specific deployment topologies belong
in the operator's private memo.

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
7. **AI-driven commits author with the operator's chosen identity.**
   Never push under a generic AI handle (e.g. "Claude AI"). The git
   config (name + email) for AI-driven commits lives in the operator's
   `local.md` private memo; load it before committing. Operators are
   free to use a persona name for their AI collaborator (e.g. "the staging host",
   "Athena", whatever they prefer) but the identity must be set
   explicitly per-machine, not assumed.
8. **No internal-detail leaks in committed files.** Operator-specific
   hostnames, usernames, internal domain names, sibling-repo names, specific
   consumer apps, and PAT or service-token names belong only in
   `%USERPROFILE%\private\local.md`. The committed tree should read like a generic OSS
   project a stranger could fork without learning the operator's setup.
9. **Phone enclave is a generic capability provider; agents inherit
   from humans.** When extending Recto's credential surface (TOTP,
   WebAuthn, PKCS#11, PGP, etc.) each new credential type adds a
   `PendingRequest.kind` constant and reuses the operator-gated
   phone-side primitive — never bypasses operator approval, never
   gives agents direct phone-side access. Agents access vault
   capabilities only via operator-issued, scoped, time-bounded JWT
   capabilities; the human's phone is the unconditional root of trust.
   Hard corollary: never design a flow where an agent can act past
   its capability's expiry, exceed its scope, or persist after
   revocation. See ARCHITECTURE.md 2026-04-26 entry for the design
   rationale.
10. **AI-driven commits use the gitscript convention, not paste-into-chat
    PowerShell blocks.** When an AI session is ready to commit + push the
    work it just authored, it writes a one-shot `git_push.ps1` script at
    the repo root containing the full staging / commit-message / commit /
    push logic, then hands the operator a 3-line execution block:
    ```
    cd <repo root>
    .\git_push.ps1
    Remove-Item .\git_push.ps1
    ```
    The script is created fresh each commit, encodes everything specific
    to that sprint (which files to stage, which leftovers to delete, the
    multi-paragraph commit message), and is deleted by the operator
    immediately after the push completes. Rationale: (a) PowerShell
    quoting hell is hostile to multi-paragraph commit messages embedded
    in a chat-pasted command; (b) the script can fail-fast on individual
    git steps with `$LASTEXITCODE` checks rather than barreling forward
    when `git add` already failed; (c) the chat-autolinking gotcha that
    converts `<word>.<py|md>` filenames into pseudo-markdown links has
    burned us before — staging a long file list in chat is exactly the
    surface that bites; (d) self-deletion after push means the script
    never lives in repo history, so each one is an AI-generated artifact
    specific to one session that doesn't accumulate. The operator may
    rename the script to `gitscript.ps1` if they prefer; `git_push.ps1`
    is the conventional default.

    **Persona identity defaults to `darwincommits` /
    `darwinsemailinbox@gmail.com` baked into the script.** The the staging host
    persona is the standing identity for AI-authored commits across
    every the operator-owned repo (Recto, AllThruit, Verso, AllThruitCoin); each
    `git_push.ps1` declares them as `param([string]$DarwinName  =
    "darwincommits", [string]$DarwinEmail = "darwinsemailinbox@gmail.com")`
    so the operator can run `.\git_push.ps1` with zero arguments and the
    OS-level Git Credential Manager popup confirming the
    darwincommits-account push is the only operator interaction
    required. NEVER make the parameters Mandatory and NEVER ask the
    operator to paste the email value into chat — that's friction the
    operator has already burned a sprint on (2026-04-29). Override-by-
    parameter still works if a future commit ever needs a different
    identity, but the default-zero-args path is the documented norm.
    The placeholder-detection sanity check at the top of every script
    stays in place as a defense against accidental clobber.

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
├── docs/                              install, service-config, secrets, threat-model
└── phone/RectoMAUIBlazor/             v0.4 phone app (MAUI Blazor) — see phone/RectoMAUIBlazor/CLAUDE.md
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

- **macOS's AF_UNIX socket path limit is 104 bytes (Linux is 108).**
  Tests that bind a Unix socket under `pytest`'s default `tmp_path`
  fail on macOS CI runners with `OSError: AF_UNIX path too long`
  because GitHub-hosted macOS runners' default TMPDIR resolves to
  `/var/folders/zz/...` and pytest layers `pytest-of-runner/
  pytest-N/test_<name>/<file>` on top — typical paths are
  120-150 chars. Fix in the workflow YAML: `mkdir -p /tmp/r`,
  then set `env: TMPDIR: /tmp/r` on every step that runs pytest.
  pytest's tmp_path_factory honors TMPDIR (it's a thin wrapper
  over `tempfile`), so this is a CI-only env tweak, no test or
  production-code change required. The 104-char limit is a
  BSD-inherited quirk in macOS's `<sys/un.h>` (sockaddr_un.sun_path
  is 104 bytes); Linux bumped it to 108 in the 2.x kernel era.
  Caught wave-7 (2026-04-29) on Recto's first GitHub-hosted-macOS
  pytest run — `test_sign_helper.py` failures cascading from
  `recto/sign_helper.py:220` socket bind. Same fix applies to any
  future test that binds Unix sockets via pytest fixtures.

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

- **NEVER `sed -i` line-range deletions on files that file tools (Read/
  Write/Edit) have touched in the same session — the bash mount and the
  Windows-side state can be out of sync, and sed will write back its
  potentially-stale view as truth.** A particularly nasty variant of the
  FUSE-mount-lag gotcha above. The flow that bit hard during the wave-7
  UI sprint (2026-04-29):
  1. Edit tool modifies `Home.razor` (Windows-side file is at full length,
     ~1900 lines)
  2. bash `wc -l` reports the file as 915 lines (stale view — actual
     length differs)
  3. AI thinks the bash view is truth, runs `sed -i '456,720d' Home.razor`
     to delete a range it can see in the bash view
  4. sed acts on the bash mount's view — but writes the result back to the
     Windows-side file via FUSE, blowing away ~1000 lines of @code block
     that the bash view had never shown
  5. `git diff --stat` shows 1243 deletions; the file is corrupt
  6. Recovery requires `git show HEAD:path > /tmp/X` then `cp /tmp/X path`
     to restore from the last commit, then re-applying changes via Edit
     tool only.

  **Hard rules to avoid this:**
  (a) Treat bash + sed/awk/grep-replace as READ-ONLY against any file
      that tools have touched this session. Use bash for read-only
      diagnostics (`grep`, `git diff`, `git show`, `wc`, `head`, `tail`).
  (b) For destructive line-range deletions across hundreds of lines,
      write a Python script that does the surgery via string-anchor
      matching (NOT line numbers), and run it via bash. The string
      anchors are stable across stale-FUSE views; line numbers are not.
  (c) Always verify post-write via Read tool, not bash `cat`. If Read
      and bash disagree on file length, Read is truth.
  (d) When in doubt, `git show HEAD:path > /tmp/path.head` to capture
      the last-known-good state at the start of the session — gives a
      one-command recovery path if anything later corrupts.

  Caught wave-7 UI sprint, lost ~30 min of session time before recovery;
  banked as a hard convention so the next sprint that mixes Python
  helper-script transformations with Edit-tool surgery doesn't stumble
  into the same pit.
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
- **Cryptographic prefix bytes are non-negotiable; cross-validate
  any new digest function against an external reference impl
  before trusting it.** EIP-191 personal_sign hashes are
  <c>keccak256(0x19 || "Ethereum Signed Message:\n" || len ||
  msg)</c> — the leading <c>0x19</c> byte is the version-discriminator
  per the spec. A C# implementation that omits it will produce
  signatures that recover correctly within its own sign + verify
  loop (internally self-consistent) but fail every external
  verifier (MetaMask, ethers, viem, Solidity's <c>ECDSA.recover</c>
  + <c>MessageHashUtils.toEthSignedMessageHash</c>). Symptom is
  invisible without a reference cross-check: end-to-end Recto-only
  testing shows "approved, signature verified, address recovered"
  while the signature would be rejected by any real consumer.
  Caught wave-4 (2026-04-28) by an xunit test that pinned the
  expected hash literal against a known external value computed
  from the canonical (correct) Python reference impl;
  Recto-internal recovery had been masking the bug. **Rule: every
  new cryptographic digest function ships with a test asserting a
  known external reference value, not just an internal-consistency
  round-trip.** Same principle applies to EIP-712 typed-data
  hashing, RLP transaction hashing, and any future BIP-32 v2
  derivation extension — pin against a value computed by another
  toolchain, not against your own sign-then-recover loop.
- **Embedded resource manifest names are <c>{RootNamespace}.{Folder}.{File}</c>;
  moving a resource between projects changes the manifest name
  and breaks lookups by literal string.** Wave-4 moved
  <c>Bip39Wordlist</c> from <c>Recto/Services/</c> to
  <c>Recto.Shared/Services/</c> and the embedded
  <c>Resources/Bip39/english.txt</c> alongside it. The loader's
  <c>GetManifestResourceStream("Recto.Resources.Bip39.english.txt")</c>
  call (using the old project's RootNamespace prefix) returned
  null after the move — silent until first use. **Rule when
  moving an EmbeddedResource between projects: update the loader's
  literal manifest-name string in the same commit. Always use the
  new RootNamespace prefix.** Mitigation pattern: when the loader
  returns null, throw a clear error naming both the expected path
  AND the source-of-truth file path so the contributor sees the
  cause immediately rather than chasing a NullReferenceException
  three frames down. Caught during wave-4 refactor 2026-04-28.

- **iCloud account on the iPhone is fully independent of the Apple
  Developer Program account on the build host.** Common first-deploy
  panic: "do I need to wipe the test phone and sign it into the
  developer's iCloud before the dev-built app will run?" No. Two
  separate concerns:
  (a) Apple Developer Program — issues code-signing certs +
      provisioning profiles, scoped by Team ID + Bundle ID + UDID.
      Lives on the build host (the the macOS host running Xcode / dotnet
      publish). Lets the build host install apps to a device whose
      UDID is registered in the profile.
  (b) iCloud account on the phone — runs Photos / Messages / App
      Store / Find My / etc. Personal services, totally orthogonal
      to dev-installed apps.
  Dev-installed apps run regardless of which iCloud (if any) is
  signed in on the device, as long as (a) is correct. **Strong
  recommendation:** never wipe a borrowed test device to "clean
  it up for development." Activation Lock (post-iOS 7) requires
  the prior iCloud user's Apple ID password during setup-after-
  erase; if that password isn't immediately available, the device
  soft-bricks until the prior user signs it out remotely from
  Find My. The provisioning + signing path doesn't need a wipe.
  Caught wave-7 (2026-04-29) on first real-iPhone deploy ceremony —
  the operator considered wiping a borrowed test device "to use
  the developer's own iCloud" before realizing the Apple Developer
  Program account on the build host was fully sufficient and the
  iCloud account was a non-factor.

- **`OSStatus -25293 errSecAuthFailed` on Secure Enclave keygen
  with an ACL of `BiometryCurrentSet | PrivateKeyUsage` means
  the device has no enrolled biometric AND/OR no device passcode
  set — NOT a code bug, NOT a provisioning problem.** Symptom:
  iPhone with Recto installed, app opens fine, user enters
  bootloader URL + pairing code, taps Pair, immediately gets
  `Secure Enclave keygen failed: The operation couldn't be
  completed. (OSStatus error -25293 - Key generation failed,
  error -25293)` BEFORE any network request fires. The keygen
  is purely local; `errSecAuthFailed` at this stage means
  Secure Enclave's policy evaluator couldn't satisfy the
  `BiometryCurrentSet` ACL. Two prerequisites the iPhone must
  have for our enclave path to mint a key:
  (a) Device passcode set (Settings → Face ID & Passcode →
      Turn Passcode On). Secure Enclave refuses to mint ANY key
      on a passcode-less device — a passcode is the root credential
      Secure Enclave uses to wrap the key material.
  (b) At least one Face ID enrollment (Settings → Face ID &
      Passcode → Set Up Face ID). The `BiometryCurrentSet` flag
      binds the key to the currently-enrolled biometric set; with
      no enrolled biometric, the policy can't be evaluated and
      keygen aborts.
  Test devices commonly skip both. **Operator fix:** enable
  passcode + enroll Face ID, then retry pairing. **Code-side
  follow-up** (open TODO): translate raw `OSStatus -25293` into
  an operator-readable message in `IosSecureEnclaveKeyService.cs`'s
  catch path — "Set up a device passcode and Face ID in iOS
  Settings before pairing" rather than dumping the OSStatus.
  Caught wave-7 (2026-04-29) during first real-iPhone smoke-test
  attempt; the error message led the operator to chase it as a
  TLS / transport problem, which it isn't (keygen is purely local
  and fires before any network call). This is the canonical
  first-iPhone-deploy stumble.

### Script-writing patterns (PowerShell + git, AI-authored)

When AI authors a one-shot PowerShell script for the operator
to run on Windows (commit + push wrappers, sanitization passes,
deploy automations, etc.), the patterns below are non-negotiable.
Each one bit during the wave-8 sanitization sprint and burnt
operator-time on diagnosis.

- **Write PowerShell scripts in pure ASCII.** Files written via
  the Write tool default to UTF-8 without BOM. Windows PowerShell
  5.1 reads UTF-8-no-BOM as Windows-1252 by default, mangles the
  multi-byte UTF-8 sequences for any non-ASCII character, and the
  parser cascade-fails with confusing errors like "Array index
  expression is missing", "Unexpected token", "missing terminator"
  — pointed at random spots downstream of the actual non-ASCII
  byte. Substitute em-dash `—` → `--`, right-arrow `→` → `->`,
  smart quotes → straight quotes, etc. Verify before handing the
  script to the operator: `python3 -c "import sys; print(sum(1
  for b in open(sys.argv[1],'rb').read() if b > 127))" path.ps1`
  must return `0`. (Caught when a sanitization-pass script's
  prose-style commit messages tripped PS5.1's parser; switched to
  ASCII and parsed cleanly.)

- **Pass Windows paths to bash subprocesses with forward-slashes
  and single-quotes.** `git filter-branch --msg-filter "python
  $winPath"` invokes the filter via bash, which interprets `\U`,
  `\A`, `\L`, `\T`, `\t` as escape sequences inside double-quotes
  and silently mangles the path. Symptom is a Python failure like
  `can't open file '...UsersErikAppDataLocalTemptmp328A.py'` —
  every backslash gone, every `\t` turned into a literal tab.
  Fix: `$pathUnix = $winPath -replace '\\','/'` then wrap in
  single-quotes inside the bash arg: `--msg-filter "python
  '$pathUnix'"`. Forward-slashes work fine on Windows for both
  Python's `open()` and git's path handling. Single-quotes
  prevent any escape processing in bash even if a stray
  backslash slips through.

- **Always use raw strings for `re.sub` replacement templates
  that contain backslashes.** Regular Python string
  `'<dev-host-home>\\'` decodes to `<dev-host-home>\` (one
  trailing backslash). `re.sub` interprets the trailing `\` as
  the start of an escape sequence, finds nothing after, and
  raises `re.error: bad escape (end of pattern) at position N`.
  Fix: `r'<dev-host-home>\\'` (raw, two literal backslashes;
  re.sub interprets `\\` as one literal `\` in output) — OR
  explicit `'<dev-host-home>\\\\'` (regular string, four-char
  escape produces two-char string). Raw is cleaner. Note this
  is DIFFERENT from PowerShell's `-replace` (.NET regex), where
  backslashes are NOT special in the replacement string at all
  — `'<dev-host-home>\'` outputs `<dev-host-home>\` with one
  backslash. Don't copy a substitution table directly between
  PowerShell `-replace` and Python `re.sub` without re-thinking
  the backslash escaping for each.

- **`git filter-branch HEAD~N..HEAD` excludes the commit at
  depth N.** Range syntax is "ancestors of HEAD that are NOT
  ancestors of HEAD~N", which gives N commits at depths 0
  through N-1. The commit at depth N (HEAD~N itself) is OUTSIDE
  the range. To rewrite all reachable history pass plain `HEAD`
  (no range, just the ref). For partial rewrites where you know
  the deepest leaky commit's depth D, use `HEAD~$($D+1)..HEAD`
  to include it. Caught when the first sanitization pass left
  five leaky commits at depths 9, 10, 11, 13, 18 — the
  `HEAD~9..HEAD` range only covered depths 0-8.

- **Use plain `--force` for one-shot AI-authored history-rewrite
  pushes; `--force-with-lease` is over-conservative when local's
  refs/remotes/origin/<branch> hasn't been refreshed.** The lease
  check compares origin's actual tip to what local THINKS origin
  is, and an outdated tracking ref makes the comparison behave
  unexpectedly. For sanitization rewrites where the AI controls
  both ends and the operator is the only pusher, plain `--force`
  is the right tool. Use `--force-with-lease` only when there's
  genuine concurrent-pusher risk on the same branch.

- **Sanitization scripts must spot-check BEFORE the push, not
  after.** A sanitization pass that finds residual leaks AFTER
  pushing leaves the public tree in a half-clean state. Phase
  ordering: scrub working-tree contents → file renames (`git
  mv`) → commit → filter-branch messages → spot-check both
  messages and tree → only THEN force-push. The script halts
  with a clear recovery instruction if the spot-check fails;
  operator iterates until clean, push happens automatically
  on the final pass.

- **Always create a backup branch before destructive history
  rewrite.** `git branch -f pre-sanitize-backup HEAD` is the
  safety net. Recovery is `git reset --hard pre-sanitize-backup;
  git push --force origin main`. Operator deletes the backup
  ONLY after eyeballing origin/main and confirming the rewrite
  landed correctly (`git ls-remote origin refs/heads/main`
  matches local HEAD).

- **`git mv` after content edits in the same script run.** When
  scrubbing a file's contents AND renaming it (operator-codename-
  named filename being replaced with a generic equivalent), order:
  edit content in-place via PowerShell, then `git mv old new`.
  `git mv` carries the modified content forward without losing
  the edit; the index sees both the rename AND the content
  change as one operation. Cross-references to the old filename
  in OTHER markdown get caught by the same content-substitution
  pass (the rename's old/new pair appears in the substitution
  table).

- **Allow-list authors-metadata files from regex sanitization.**
  A `\b<personal-name>\b -> the operator` substitution over a
  regex-only file scrub will mangle `pyproject.toml`'s legal
  Apache-2.0 author attribution: a hypothetical
  `authors = [{name = "Foo Bar"}]` becomes
  `authors = [{name = "the operator Bar"}]` if the substitution
  matches the personal name. The author attribution is
  legitimate metadata, not an operator-context leak. Approach:
  per-file allow-list excludes `pyproject.toml` (and similarly
  `LICENSE`, `AUTHORS`, `CONTRIBUTORS.md`, etc.) from the regex
  pass; scrub everything else. The post-rewrite spot-check
  step similarly excludes those files from the working-tree
  leak scan.

- **Filter-branch needs `-f` if `.git-rewrite/` exists from a
  prior failed run.** Symptom: `A previous backup already
  exists in refs/original/`. Fix: pass `-f` to overwrite.
  AI-authored sanitization scripts should always pass `-f`
  since the operator may be retrying after an earlier abort.

### Application-substrate patterns banked from wave-8

- **Mock-bootloader / dev-tools scripts: self-locate the
  package root at module-import time.** Pattern at the top of
  any dev-tools script that imports first-party packages:
  ```python
  _repo_root = pathlib.Path(__file__).resolve().parents[N]
  if (_repo_root / "package").is_dir() and str(_repo_root) not in sys.path:
      sys.path.insert(0, str(_repo_root))
  ```
  Sidesteps `No module named X` errors when the script is
  invoked from a non-rooted Python (build cache, `PYTHONPATH`-
  stripped wrapper, IDE-launched without project root, etc.).
  The `N` parameter is the script's depth below the repo root;
  verify by computing `_repo_root` and confirming
  `(_repo_root / "package").is_dir()` succeeds. Without this,
  operator-facing UI rows fall through to "address recovery
  failed: No module named '<pkg>'" warnings next to perfectly-
  valid signatures — looks like a real bug to non-implementer
  operators.

- **Per-coin / per-chain discriminator-field assignment must
  be OUTSIDE any `try` over an optional library import.** When
  the operator-UI render path dispatches on a discriminator
  (`btc_coin`, `ed_chain`, etc.) for ticker labels, the
  field MUST be set BEFORE the try block that imports the
  optional verifier library. If inside the try, an `ImportError`
  leaves the field unset, the renderer falls back to a default
  ticker, and operators see (e.g.) "BTC message_signing" next
  to a Litecoin login. Operators approving signing requests
  under wrong tickers is exactly the failure mode that drops
  on-chain authority to the wrong chain. Pattern:
  ```python
  # CORRECT — discriminator set unconditionally
  extra_response_fields["btc_coin"] = coin_btc
  try:
      from package.bitcoin import recover_address
      # ... use it ...
  except ImportError:
      extra_response_fields["btc_recovery_error"] = "module unavailable"

  # WRONG — discriminator is lost on import failure
  try:
      from package.bitcoin import recover_address
      extra_response_fields["btc_coin"] = coin_btc
      # ...
  except ImportError:
      pass
  ```
  Same pattern applies to any future multi-coin or multi-chain
  discriminator. Caught wave-7-retroactive during the wave-8
  ed25519-trio smoke when the macOS host's mock didn't have the
  package on PYTHONPATH and every BTC-family row rendered with
  the "BTC" default ticker regardless of `btc_coin`.

- **Operator-facing label dispatch: every render path must use
  the discriminator field, not hardcoded strings.** Pending-row
  labels, response-row labels, approval-card UI, and any other
  surface that emits a coin/chain ticker MUST each dispatch
  through the same `{discriminator: ticker}` mapping. Hardcoded
  string prefixes (e.g. "BTC " inside a label string) silently
  produce wrong tickers when the discriminator is non-default.
  Audit checklist when adding a multi-coin discriminator: grep
  for every place the family-default ticker appears as a literal
  string and convert each to a dispatch lookup against the
  discriminator field.

- **BIP-137 header byte must dispatch on coin -- "shared
  primitive across coins" sprints have to audit every layer
  where the address kind is encoded, not just the obvious ones.**
  Wave-7 added LTC + DOGE + BCH on top of BTC by sharing the
  secp256k1 primitive across the family and dispatching the
  signed-message preamble per coin. Layer that the sprint
  caught: `SignedMessageHash(message, coin)` picks the right
  "X Signed Message:\n" magic. Layer the sprint MISSED: the
  BIP-137 compact-signature header byte ALSO encodes which
  address kind the verifier should use to encode the recovered
  hash160 (BIP-137 "Header byte values"):
  - 27..30 = P2PKH uncompressed (legacy)
  - 31..34 = P2PKH compressed
  - 35..38 = P2SH-P2WPKH (nested SegWit)
  - 39..42 = P2WPKH (native SegWit)

  Pre-fix, `SignCompactBip137` hardcoded `header = 27 + 12 +
  recId = 39..42` regardless of coin. BTC + LTC kept working
  because both have native SegWit (bech32 HRPs `bc` and `ltc`).
  DOGE + BCH BROKE because their `default_address_kind` is
  `p2pkh` and they have no bech32 HRP at all -- the verifier's
  `recover_address(coin=...)` parsed `address_kind="p2wpkh"`
  out of the header byte, then tried to encode the recovered
  hash160 as bech32, then raised `<coin> does not support
  native SegWit (P2WPKH); use kind='p2pkh' instead`.

  Crucially the underlying ECDSA signature itself was VALID
  on every coin -- the chain-side "verify the secp256k1 sig"
  check passed -- so the smoke test green-checked the chain
  signature while the address-recovery branch raised. End
  result on the operator UI: "approved -- chain sig verified
  -- address recovery failed: <coin> does not support native
  SegWit". Looks scary, no real security impact, but if a
  real verifier (a wallet, a chain explorer) ever tried to
  derive the signer address from one of these sigs, it would
  hit the same wall and reject.

  **Fix shape (Wave-7-retroactive, 2026-04-30)**: thread the
  coin through `SignCompactBip137(msgHash, privateKey, coin)`,
  look up `cfg.DefaultAddressKind` from the COIN_CONFIG table,
  map address kind to header offset (`p2pkh-uncompressed=0`,
  `p2pkh=4`, `p2sh-p2wpkh=8`, `p2wpkh=12`), and emit
  `header = 27 + offset + recId`. Pin per-coin header-byte
  ranges in `BtcSigningOpsTests.cs` so a future "share the
  primitive across coins" sprint that adds (e.g.) Zcash gets
  the regression caught at unit-test time.

  **Sibling rule with the discriminator-field-outside-try-block
  gotcha above**: both are "multi-coin primitive must dispatch
  on the discriminator at every layer where the discriminator
  matters." The first one is about the response-field LABELING
  layer; this one is about the SIGNATURE SERIALIZATION layer.
  Audit checklist when adding a new coin to an existing
  family: (a) preamble / message format -- usually obvious;
  (b) address derivation -- usually obvious; (c) signature
  serialization format -- often hides discriminator-encoded
  fields (header bytes, version flags, "type" tags) that look
  shared across the family but actually aren't; (d) verifier
  re-derivation path -- whatever shape the sig got serialized
  in must round-trip correctly under the verifier's same-coin
  parse path.

### Phone-app gotchas → moved

The MAUI / iOS / Android phone-app gotchas (build / sign / Razor /
enclave / etc.) used to live in this index. They were extracted to
`phone/RectoMAUIBlazor/CLAUDE.md` to keep this file focused on
substrate concerns. If you're working anywhere under `phone/`,
read that file in addition to this one.

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
- **First "true vault-only" consumer state reached 2026-04-28.**
  Closing pass on a consumer's two-phase migration: the plaintext
  `.env` file that Phase A relied on (transcribed into NSSM
  `AppEnvironmentExtra` so the migrator had something to read) was
  deleted from the staging server. The consumer now runs with no
  secret value on disk in plaintext anywhere on the host: every
  secret lives in dpapi-machine-encrypted blobs that the launcher
  decrypts at child-spawn and injects into the spawned child's env;
  no secret is in NSSM `AppEnvironmentExtra` (the launcher reads
  YAML + vault, not the registry); no secret is in any working tree.
  The other consumer reached the same state the same day. Validates
  the substrate's design intent — `.env` files are a migration aid,
  not a long-term posture — and proves the dpapi-machine backend is
  trusted enough to be the sole source of truth for production
  secrets. A new secret minted later the same day (a freshly-issued
  third-party API token) was stored vault-only from inception, never
  passing through `.env` or `AppEnvironmentExtra`; that's the
  expected default for any new secret going forward.

- **First real-iPhone deploy + Secure Enclave smoke tests 2026-04-29.**
  the test device running iOS 17.x, deployed via `dotnet publish` +
  `xcrun devicectl device install` from a the macOS host mini build host under
  an Apple Developer Program account (Team ID-bound provisioning
  profile registering the device UDID). Pairing screen reported
  `signing algorithm: ecdsa-p256`, confirming the
  `IosSecureEnclaveKeyService` Secure-Enclave path drove — NOT
  the cross-platform software fallback. All five coin families
  signed end-to-end on real hardware: ed25519 envelope, secp256k1
  + EIP-191 (ETH), and secp256k1 + BIP-137 across BTC + LTC +
  DOGE + BCH. Every approval round-tripped through the comms
  layer back to the mock bootloader, which recovered the signer
  address and reported ✓. Dark vault UI rendered correctly on
  iOS WKWebView with no platform-specific layout regressions.
  This is the first time the v0.5+ Secure-Enclave code paths
  ran against real hardware (previously written + unit-tested
  only). Real-iPhone deploy validation gate closed; the
  architectural bet (phone-resident vault + Secure Enclave as
  root of trust + one mnemonic deriving five coin trees) is now
  validated end-to-end.

## Active sprint — Wave 9: TRON — parts 1 + 2 SHIPPED 2026-04-30; iPhone smoke VALIDATED 2026-04-30; coverage 20/21 (95.2%) hardware-proven

Wave 9 follows the Wave 6/7/8 split pattern: Python verifier
+ protocol DTOs landed first (commit earlier today), C# phone-side
landed in this commit. Wave 9 takes coin coverage from 19/21 (90.5%,
post-Wave 8) to 20/21 (95.2%) end-to-end (phone-side signing AND
Python-side verification). Cardano (ADA, the remaining 1) ships in
Wave 10 when its custom SLIP-23 / CIP-1852 derivation lands.

**Wave 9 part 2 deliverables (this commit)** -- full detail in
CHANGELOG.md `[Unreleased]`:

- `Recto.Shared/Services/TronSigningOps.cs` (math layer): TIP-191
  hash with the load-bearing leading 0x19 byte, base58check encoder
  (Bitcoin alphabet + double-SHA-256 checksum), TRON address
  derivation from 64-byte uncompressed pubkey, sign + recover
  delegating to `EthSigningOps` (same secp256k1 curve and
  v-recovery pipeline byte-for-byte).
- `Recto.Shared/Services/ITronSignService.cs` interface +
  `Recto.Shared/Models/TronAccount.cs` value object.
- `Recto/Services/MauiTronSignService.cs` SecureStorage-backed
  orchestrator -- reads the SHARED mnemonic
  (`recto.phone.eth.mnemonic.{alias}`) that ETH/BTC/ED already
  provision; derives at `m/44'/195'/0'/0/N`. One mnemonic, nine
  chain trees (ETH, BTC, LTC, DOGE, BCH, SOL, XLM, XRP, TRON).
- Protocol DTOs: `PendingRequestKind.TronSign`, `TronMessageKind`,
  `TronNetwork` enums in `PendingRequest.cs`; six `tron_*` fields
  on `PendingRequestContext`; `TronSignatureRsv` on `RespondRequest`.
- `Home.razor`: TRON render arm + `ApproveTronSignAsync` dispatcher
  + `PopulateTronAddressesAsync` hooked into `RefreshPendingAsync`
  + per-coin helpers (`_tronMessageKindLabel`, `_tronNetworkLabel`)
  + `IsTokenSigningKind` extended + new red TRX badge.
- `app.css` + `Home.razor.css`: `--rec-coin-tron` Tronix-red
  variable + `.rec-coin-badge-tron` class.
- `MauiProgram.cs`: `ITronSignService` -> `MauiTronSignService`
  cross-platform singleton DI registration.
- `Recto.Shared.Tests/TronSigningOpsTests.cs`: 11 tests pinning the
  canonical generator-G TRON address (cross-pinned with
  `tests/test_tron.py`'s `TMVQGm1qAQYVdetCeGRRkTWYYrLXuHK2HC`),
  TIP-191 hash distinctness vs EIP-191, ASCII-decimal length-byte
  encoding, sign-then-recover round-trip.

**iPhone smoke VALIDATED 2026-04-30**: re-deploy + smoke on the
test device landed clean. Phone displayed the TRON request with
red TRX badge, mainnet, derivation path `m/44'/195'/0'/0/0`,
derived address `TVm1H9XYdGKGnT5goozq3moyXmZtRgwtrJ`. Approve
produced a 65-byte r||s||v signature; mock bootloader recovered
the signer address from the rsv and it matched the phone-derived
address byte-for-byte. Green "verified" pill. POST /v0.4/respond
returned 200. Coverage 20/21 (95.2%) hardware-proven end-to-end.

A same-day hotfix landed during the smoke run: the mock-
bootloader's tron_sign envelope-verify branch had used
`target_phone` (queue-handler-only variable) instead of `phone`
(respond-handler scope), throwing UnboundLocalError on every
approve. Caught by my own try/except, surfaced as a 400 to the
phone. Fix aligned the branch with the eth_sign canonical
envelope-verify pattern + removed the broken catch-all so future
tron-branch exceptions bubble up to BaseHTTPRequestHandler's
default exception handler (writes tracebacks to stderr -> log).

**Cross-wave priorities still unblocked** (unchanged from Wave 8
closure, plus one new banked-for-investigation item):
- Capability-JWT scope semantics for agent signing (AllThruitCoin
  Phase 5 unlock).
- Mnemonic export/import ceremony UIs.
- Multi-account picker.
- PSBT (BIP-174) signing.
- Friendlier `OSStatus -25293` translation in iOS Secure Enclave
  catch path.
- **Investigate phone-side auto-unpair after ETH typed_data
  approval** (banked 2026-04-30 during the post-Wave-9 full-
  coin-family smoke). Signature flow itself works correctly --
  bootloader recorded the verified response before the unpair
  fired -- but the next polling-loop iteration's
  `TaskCanceledException` ends with the phone reverting to "Not
  paired yet". Two leading hypotheses: (a) post-approve render
  path disposes the page component, cancelling the polling
  CancellationToken, and a catch path in the polling loop wrongly
  interprets cancellation as "phone has been revoked"; (b)
  `ApproveEthTypedDataAsync` has a kind-specific cleanup branch
  that wrongly clears pairing state. Phone-side bug only; other
  card types unaffected. Repro: queue ETH typed_data after pairing,
  approve on phone, watch for self-unpair on the next GET /pending.

---

## Prior sprint — Wave 9 part 1 (Python verifier + protocol DTOs + mock-bootloader integration, 2026-04-30)

Foundation pass for Wave 9. The Python verifier shipped with 22
tests covering TIP-191 hash pinning, the canonical generator-G TRON
address, and sign-then-verify round-trips. Protocol DTOs in
`PendingRequest.new_tron(...)` + `_pending_to_wire` emit + 
`_handle_respond` structure-check + `_notify_resolved` extension.
Mock bootloader gained a queue endpoint, button, verifier branch,
and recent-responses display row. Operator validated end-to-end on
the dev workstation: 22/22 tests pass, MAUI loads fine, paired phone
fetches the queued `tron_sign` request (rendered as "Unknown request
kind" because Wave 9 part 2's render arm hadn't shipped yet -- exactly
the expected state at the part-1 boundary).

---

## Prior sprint — Wave 8: ed25519 trio (SOL + XLM + XRP) — parts 1 + 2 SHIPPED 2026-04-29; iPhone smoke VALIDATED 2026-04-30; cross-wallet interop deferred

Wave 9 follows the Wave 6/7/8 split pattern: Python verifier
+ protocol DTOs ship first (this commit), C# phone-side ships
second. Wave 9 takes coin coverage from 19/21 (90.5%, post-Wave 8)
to 20/21 (95.2%) at the protocol layer. The remaining 1 coin
(Cardano/ADA) ships in Wave 10 when its custom SLIP-23 / CIP-1852
derivation lands.

**Wave 9 part 1 deliverables (this commit, 2026-04-30)** -- full
detail in CHANGELOG.md `[Unreleased]`:

- `recto.tron` Python module: TIP-191 hash, base58check
  address encoding (`base58check(0x41 || keccak256(pubkey64)[-20:])`),
  recover-public-key + recover-address, verify-round-trip helper.
  Reuses `recto.ethereum.keccak256` / `recover_public_key` directly.
- `recto[tron]` optional extra (empty list -- pure stdlib + delegation
  to `recto.ethereum`).
- `PendingRequest.new_tron(...)` constructor + six new `tron_*` context
  fields. Mirrors `new_btc` shape; refuses `transaction` kind for now
  (reserved for a follow-up wave when TRON's protobuf transaction
  parser lands).
- `_pending_to_wire` emits `tron_*` when `kind == "tron_sign"`;
  `_handle_respond` structure-checks `tron_signature_rsv`;
  `_notify_resolved` extends with the new tron kwarg + TypeError-fallback
  tier for backward compat with pre-Wave-9 callbacks.
- Mock bootloader: queue endpoint + button + verifier branch +
  recent-responses display row. Placeholder-address suppression for
  the dev-side `TPlaceholder...` sentinel.
- 22 tests in `tests/test_tron.py` (all passing locally) pinning the
  TIP-191 hash, the canonical generator-G TRON address, and the
  sign-then-verify round-trip. ~25 tests in
  `tests/test_bootloader_tron.py` covering construction validation
  + live HTTP scenarios (Windows-side pytest pending due to the
  FUSE-lag gotcha after edits to `state.py` / `server.py` -- bash
  sandbox sees truncated views; Read tool sees the actual files
  cleanly; Edit tool's success messages are authoritative).

**Wave 9 part 2 (next)** -- C# phone-side. Sister implementation
of Wave 6 part 1 (ETH C#), structurally simplest of the wave-9
work since the secp256k1 primitive is already in
`EthSigningOps.SignWithRecovery` and `MauiEthSignService`'s BIP-39
mnemonic + Bip32 derivation reuse for free. Net-new:

- `Recto.Shared/Services/TronSigningOps.cs` -- TIP-191 hash,
  base58check encoder (with the same Bitcoin alphabet as
  Solana / Bitcoin's BTC encoder), address derivation from
  uncompressed pubkey, recovery-id discovery.
- `Recto.Shared/Services/ITronSignService.cs` interface +
  `Recto.Shared/Models/TronAccount.cs` value object.
- `Recto/Services/MauiTronSignService.cs` SecureStorage-backed
  orchestrator. SAME `MnemonicPrefix = "recto.phone.eth.mnemonic."`
  as the ETH/BTC/ED services; one mnemonic, nine chain-coin trees.
- Protocol DTOs in `Recto.Shared/Protocol/V04/`:
  `PendingRequestKind.TronSign` + `tron_*` fields on
  `PendingRequestContext` + `TronSignatureRsv` on `RespondRequest`.
- `Recto.Shared/Pages/Home.razor` render arm for `tron_sign`
  + `ApproveTronSignAsync` dispatcher + per-chain helpers
  (`_tronNetworkBadgeClass`, `_tronTickerLabel`, etc.).
- New per-coin badge color in `app.css` for TRON (Tronix red).
- `Recto.Shared.Tests/TronSigningOpsTests.cs` pinning the canonical
  generator-G TRON address against the same Wave 9 part 1 vector,
  plus per-message hash distinctness vs EIP-191.

After Wave 9 part 2 ships and lands an iPhone smoke validation:
coverage hits 20/21 hardware-proven on the test device.

**Cross-wave priorities still unblocked** by hitting the 80% gate
(unchanged from Wave 8 closure):
- Capability-JWT scope semantics for agent signing (AllThruitCoin
  Phase 5 unlock).
- Mnemonic export/import ceremony UIs.
- Multi-account picker.
- PSBT (BIP-174) signing.
- Friendlier `OSStatus -25293` translation in iOS Secure Enclave
  catch path.

---

## Prior sprint — Wave 8: ed25519 trio (SOL + XLM + XRP) — parts 1 + 2 SHIPPED 2026-04-29; iPhone smoke VALIDATED 2026-04-30; cross-wallet interop deferred

Goal: maximize coin throughput per sprint window. the operator's target
list is 21 coins; XMR / ZCASH / CC explicitly skipped (privacy-by-
design or institutional-architecture mismatch with Recto's
self-custody model). Wave-by-wave plan ordered by leverage:
chains that share infrastructure unlock multiple coins per wave.

**Coverage state entering this sprint: 16 of 21 top coins** signing
through Recto, validated end-to-end on the test device hardware
(2026-04-29). Wave 8 part 1 (Python verifier + protocol DTOs)
landed today, putting ed25519-trio coverage at the protocol layer;
part 2 (phone-side C# signing) plus iPhone smoke tests close the
loop and bring coverage to 19 of 21 (90.5% — past the 80% gate that
was holding the cross-wave priorities below).

Recently shipped — all detail in `Prior sprints (shipped)` below +
dated CHANGELOG entries:
- **Wave 6** — EVM expansion + EIP-712 typed-data + EIP-1559
  transaction (2026-04-29). Unlocked 8 EVM-family coins.
- **Wave 7** — Bitcoin family extension (LTC + DOGE + BCH) via
  `btc_coin` discriminator (2026-04-29). +3 coins.
- **macOS-side pivot** — macOS pytest CI on GitHub-hosted runners +
  iOS device deploy ceremony (2026-04-29). Unblocked iPhone smoke
  tests.
- **the test device smoke tests** — first time the v0.5+ Secure-Enclave
  code paths ran on real hardware. All five coin families approved
  end-to-end. Architectural bet validated.

### Wave 8 part 1 — Python verifier + protocol DTOs (2026-04-29)

Sister implementation of Wave 6 (ETH) and Wave 7 (BTC family) for
the ed25519 chain family. Reuses zero curve code from those waves
(secp256k1 vs ed25519 are different curves) but mirrors their
protocol shape exactly: one credential kind (`ed_sign`), one
discriminator field (`ed_chain` ∈ `{sol, xlm, xrp}`), one config
table per chain holding the per-chain BIP-44 path / address
encoding / message preamble.

**Architecture**: one BIP-39 mnemonic per phone (shared with the
existing `MauiEthSignService` and `MauiBtcSignService`), three new
SLIP-0010 ed25519 trees (all-hardened paths because SLIP-0010 ed25519
doesn't support non-hardened derivation):
- SOL: `m/44'/501'/N'/0'` → base58(pubkey32) addresses (no checksum,
  Bitcoin alphabet — Phantom / Solflare convention)
- XLM: `m/44'/148'/N'` → StrKey `G…` addresses (RFC-4648 base32
  with version byte 0x30 + CRC16-XMODEM checksum, SEP-0005 / SEP-0023)
- XRP-ed25519: `m/44'/144'/0'/0'/N'` (Xumm / XRPL ed25519 convention)
  → classic `r…` addresses (Ripple-flavored base58 with version byte
  0x00 + Base58Check checksum + 0xED ed25519 prefix on pubkey
  pre-image — XRP discriminates ed25519 from secp256k1 by prefixing
  the raw pubkey with 0xED before HASH160ing into the AccountID)

One backup ceremony covers all five coin families now (ETH, BTC,
LTC, DOGE, BCH, SOL, XLM, XRP). 24 words, eight chain trees.

**Wave 8 part 1 deliverables (this commit)**:
- `recto.solana` Python module — base58 encoding (Bitcoin alphabet,
  no checksum), SOL address derivation, signed-message hashing with
  Recto's chosen preamble (`b"Solana signed message:\n"`), ed25519
  signature verification (delegates to `cryptography`).
- `recto.stellar` Python module — RFC-4648 base32 StrKey encoding,
  CRC16-XMODEM (pure-Python bit-by-bit reference impl, pinned
  against the canonical "123456789" → 0x31C3 vector), XLM address
  derivation, signed-message hashing.
- `recto.ripple` Python module — Ripple-alphabet base58 (distinct
  from Bitcoin's; alphabet pinned), XRP-flavored Base58Check, 0xED
  ed25519 prefix handling, AccountID derivation via HASH160 (borrows
  `recto.bitcoin.ripemd160`), classic-address encoding, signed-
  message hashing. Verifier requires BOTH the signature AND the
  pubkey because XRP addresses are one-way HASH160s.
- `recto[ed25519]` extra in `pyproject.toml` (empty list — gates the
  import path; `cryptography` only needed for signature verification
  and is already pulled by `recto[v0_4]`).
- `PendingRequest.new_ed(...)` constructor in `recto.bootloader.state`
  with construction-time validation matching Wave 7's `new_btc`
  pattern. Six new optional `ed_*` fields on the `PendingRequest`
  dataclass.
- `_pending_to_wire` emits `ed_*` fields when `kind == "ed_sign"`
  (omitted otherwise — regression test pins this).
- `_handle_respond` structure-checks `ed_signature_base64` (64-byte
  decode) AND `ed_pubkey_hex` (64 hex chars after optional 0x prefix
  strip — XRP needs the explicit pubkey because addresses lose pubkey
  info; SOL and XLM technically don't but carry it for protocol
  uniformity). `_notify_resolved` extends to forward both new fields
  alongside the existing eth/btc fields, with the same TypeError
  fallback chain so older test fixtures still match.
- 65+ new tests across `tests/test_solana.py`, `tests/test_stellar.py`,
  `tests/test_ripple.py`, `tests/test_bootloader_ed.py` — pin the
  encoding primitives against external reference values where
  possible (CRC16, alphabet character orderings, SOL System Program
  pubkey → "11111111111111111111111111111111"), round-trip the rest
  (encode-decode, sign-verify), and exercise the bootloader's
  validation paths end-to-end against a live HTTP loopback.

### Wave 8 part 2 — C# phone-side (2026-04-29)

C# half of Wave 8, sister implementation to Wave 6 (ETH C#) and
Wave 7 (BTC C#) but for the ed25519 chain family. Same one-mnemonic-
shared-across-services posture: ETH + BTC + ED services all read
the same `recto.phone.eth.mnemonic.{alias}` SecureStorage entry,
each derives at its own curve / path tree.

**Deliverables (this commit)**:
- `Recto.Shared/Services/Slip10.cs` — SLIP-0010 ed25519 derivation
  (HMAC-SHA512 with key `"ed25519 seed"`, BouncyCastle ed25519
  scalar mult for pubkey-from-private). Hardened-only — non-hardened
  paths throw at `ParsePath` time. Sister of `Bip32` for ed25519.
- `Recto.Shared/Services/Ed25519ChainSigningOps.cs` — single static
  class covering all three chains via a per-chain `ChainConfig`
  table. Mirrors Wave 7's `BtcSigningOps` shape: `SignedMessageHash`
  / `AddressFromPublicKey` / `SignMessage` all chain-aware. Address
  encoders for SOL (Bitcoin-alphabet base58 no checksum), XLM
  (RFC-4648 base32 StrKey + CRC16-XMODEM), XRP (Ripple-alphabet
  Base58Check + 0xED ed25519 prefix on pubkey pre-image + RIPEMD-160
  via BouncyCastle). All curve-free except the actual ed25519 sign
  primitive.
- `Recto.Shared/Services/IEd25519ChainSignService.cs` — interface +
  `EdSignResult(SignatureBase64, PublicKeyHex)` value-returning
  contract. Public key hex is required because XRP addresses are
  HASH160s and don't carry the pubkey; SOL/XLM carry it for
  protocol uniformity.
- `Recto.Shared/Models/EdAccount.cs` — value object mirroring
  `EthAccount` / `BtcAccount`.
- `Recto/Services/MauiEd25519ChainSignService.cs` — SecureStorage-
  backed implementation. SAME `MnemonicPrefix = "recto.phone.eth.mnemonic."`
  as the ETH/BTC services. ZeroMemory-wipes seed + leaf private
  key + chain code in `finally` blocks per the existing pattern.
  Single cross-platform DI registration in `MauiProgram.cs` (no
  per-platform fan-out — neither iOS Secure Enclave nor Android
  StrongBox natively support SLIP-0010 ed25519 derivation, so the
  software BouncyCastle path IS the implementation).
- `Recto.Shared/Protocol/V04/PendingRequest.cs` — `PendingRequestKind.EdSign`
  constant + `EdChain` enum class (Solana / Stellar / Ripple) +
  `EdMessageKind` enum class (MessageSigning / Transaction).
- `Recto.Shared/Protocol/V04/PendingRequestContext.cs` — six new
  optional ed_* fields mirroring Python's state.py shape.
- `Recto.Shared/Protocol/V04/RespondRequest.cs` — `EdSignatureBase64`
  + `EdPubkeyHex` fields on the union response shape.
- `Recto.Shared/Pages/Home.razor` — render arm for `ed_sign` (chain-
  specific badge + chain name + path + derived address + message
  text), `ApproveEdSignAsync` dispatcher producing the dual signature
  (chain ed25519 sig + Ed25519 envelope). Pre-derive cache
  `_edAddressByRequestId` populated in `RefreshPendingAsync`.
  `IsTokenSigningKind` updated so ed_sign lands in the Crypto
  Tokens section. Per-chain helpers: `_edChainBadgeClass` / 
  `_edChainTickerLabel` / `_edChainDisplayName` / 
  `_edDefaultPathForChain` / `_edMessageKindLabel`.
- `Recto.Shared/wwwroot/app.css` + `Pages/Home.razor.css` — new
  per-coin badge color variables (SOL Phantom-purple `#9945ff`,
  XLM Stellar-blue `#14b6e7`, XRP `#23292f`) and the matching
  `.rec-coin-badge-{sol,xlm,xrp}` classes.
- `phone/RectoMAUIBlazor/dev-tools/mock-bootloader.py` — three new
  operator-UI buttons + endpoint handlers (`/_queue_sol_message_sign`
  / `/_queue_xlm_message_sign` / `/_queue_xrp_message_sign`) that
  mint a login-style message and queue an `ed_sign` PendingRequest.
- `Recto.Shared.Tests/Slip10Tests.cs` — derivation determinism +
  hardened-only enforcement + cross-curve distinctness from BIP-32
  (the SLIP-0010 / BIP-32 master keys MUST differ for the same seed
  because the HMAC keys differ).
- `Recto.Shared.Tests/Ed25519ChainSigningOpsTests.cs` — CRC16
  canonical pin, Ripple alphabet pin, SOL System Program (32 zero
  bytes pubkey → 32 ones address), per-chain message preamble pins,
  cross-chain hash distinctness (same message + different chain →
  different hash), end-to-end sign-then-verify round-trip with a
  BouncyCastle Ed25519Signer.

**Coverage now**: 19 of 21 target coins (90.5%). Past the 80% gate
that was holding the cross-wave priorities below. iPhone smoke
landed 2026-04-30 -- SOL/XLM/XRP rows hardware-proven on the test
device alongside the wave-7-retroactive BIP-137 header-byte fix
(see CHANGELOG.md). Cross-wallet interop pinning is the only
remaining item: verify mnemonic-derived addresses against Phantom
(SOL), Stellar Lab (XLM), and Xumm (XRP).

**Wave 9 — TRON (ACTIVE AFTER WAVE 8 part 2).** secp256k1 +
Keccak-256 + base58 address; close cousin of ETH. Reuses
`EthSigningOps.SignWithRecovery` directly; net-new is the address
derivation (Keccak-256 of pubkey, last 20 bytes, base58check with
TRON's version byte 0x41) and the BIP-44 path (`m/44'/195'/0'/0/N`
— note this is the secp256k1 BIP-32 path, NOT SLIP-0010 since TRON
uses secp256k1).

**Wave 10 — Cardano (ADA).** ed25519 with custom derivation
(BIP-44 + Cardano's own SLIP-23 / CIP-1852 hardened-key tweak).
Deferred to its own wave; the derivation path is non-standard
enough that a reusable primitive doesn't fall out of the
existing Bip32 work.

**Skipped:** XMR (privacy-by-design — view keys + ring sigs
require a different architectural posture); ZCASH (zk-SNARK
proving requires multi-second compute on shielded transfers,
mismatch with phone-tap-approve flow); CC = Canton (#16 by mcap;
institutional permissioned-ledger architecture, not self-
custody). Reserved for a future "exotic chains" sprint if
demand emerges.

**Cross-wave priorities (deferred until coin coverage hits 80%+):**
- **Capability-JWT scope semantics** for agent signing —
  AllThruitCoin Phase 5 unlock; the path that lets agent-script
  features sign on-chain on behalf of operators within scoped
  caps.
- **Mnemonic export ceremony** — biometric-gated one-time-display
  UI so operators can back up the 24 words.
- **Mnemonic import ceremony** — paste an existing mnemonic
  (e.g. from a Ledger recovery phrase).
- **Multi-account picker** — Settings page listing every address
  derived so far.
- **PSBT (BIP-174) signing** — Bitcoin transaction signing.
- **Friendlier `OSStatus -25293` translation** in
  `Platforms/iOS/IosSecureEnclaveKeyService.cs` catch path —
  emit "Set up a device passcode and Face ID in iOS Settings
  before pairing" instead of dumping the raw OSStatus to the
  operator. Open TODO banked from wave-7 iPhone-11 smoke test
  (the first-iPhone-deploy stumble).

---

## Prior sprints (shipped)

### Wave 7 — Bitcoin family extension (LTC + DOGE + BCH) (2026-04-29)

Extends `btc_sign` from "Bitcoin only" to four coins via a single
`btc_coin` discriminator field. Same crypto primitives across the
family; per-coin differences (preamble, version bytes, bech32 HRP,
BIP-44 coin type, default address kind) live in a single
COIN_CONFIG table mirrored between Python (`recto.bitcoin`) and
C# (`BtcSigningOps.CoinConfigs`). Adding a fifth coin = one entry
in each table plus a test vector. No new credential kinds, no new
RFC fields beyond the optional `btc_coin` discriminator, no
breaking changes to v0.5 phones (absent / null `btc_coin` defaults
to "btc").

**Coverage unlocked.** Three more of the user's top-21 target coins
activated:
- **LTC (Litecoin)** — `m/84'/2'/0'/0/N` native SegWit P2WPKH
  (`ltc1q...`) with HRP `ltc`. Litecoin Signed Message preamble.
- **DOGE (Dogecoin)** — `m/44'/3'/0'/0/N` legacy P2PKH (`D...`,
  version byte 0x1E). Dogecoin Signed Message preamble.
- **BCH (Bitcoin Cash)** — `m/44'/145'/0'/0/N` legacy P2PKH
  (`1...`, version byte 0x00 — same as BTC's legacy form). BCH
  retained Bitcoin's signed-message preamble post-fork; only
  the BIP-44 coin type and forward CashAddr surface differ.

Wave shipped in two consecutive parts the same day: Wave 7 part 1
(UI redesign with vault-aesthetic dark theme + IDENTITY/CRYPTO
section split + per-coin badge classes + Python coin parameter)
and Wave 7 part 2 (C# protocol DTOs + state.py + bootloader
server + mock UI buttons + C# coin parameter + Razor render-arm
+ 11 new tests). All five coin families later validated on iPhone
11 hardware (see iPhone smoke-test entry below).

### Wave 6 — EVM expansion + EIP-712 + EIP-1559 (2026-04-29)

Single highest-leverage move: extends `m/44'/60'` BIP-44 tree to
21 EVM-compatible chains (mainnet + 6 L2s + 7 sidechains/alt-L1s
+ 7 testnets) with all three signing verbs wired end-to-end —
EIP-191 personal_sign (already shipped), EIP-712 typed_data (new),
EIP-1559 (type-2) transaction (new). Unlocks 8 of 21 target coins
in one wave: ETH (mainnet+L2s), BNB Smart Chain, AVAX C-chain,
USDT, USDC, DAI, LINK, HYPE, USD1.

Net-new primitives: `typed_data_hash` + `transaction_hash_eip1559`
in Python, `EthSigningOps.SignAndEncodeTransactionEip1559` +
`SignAndEncodeTypedData` in C#, RLP encoding helpers, mock
bootloader operator UI for queueing typed-data + transaction
requests, address-recovery on the verify side. EVM chain-id
constants live in a single `EvmChain` enum mirrored Python ↔ C#.

### macOS-side pivot — macOS pytest CI + iOS device deploy (2026-04-29)

Recto's test + deploy surface expanded to cover macOS end-to-end:

  1. **macOS pytest CI** via GitHub-hosted `macos-latest` runners
     in `.github/workflows/test-the macOS host.yml`. The substrate is a public
     OSS repo, and self-hosted runners on public repos are an
     attack vector (any fork can submit a PR with a malicious
     workflow that executes on the runner — documented
     cryptominer-via-PR pattern). GitHub-hosted runners sidestep
     this: ephemeral VM per job, free for public repos, no
     machine-side setup. Unlocks ~17 platform-gated tests that
     skip on Windows (`test_sign_helper` Unix-socket flow,
     `test_joblimit` Linux/macOS Win32-Job-Object guards,
     `test_secrets_credman` / `test_secrets_dpapi_machine`
     "Windows only" reverse-gates, `test_adminui` SO_REUSEADDR
     semantics).
  2. **iOS device deploy** stayed macOS-host-local because it needed a
     physical iPhone connected via USB — GitHub-hosted runners
     can't do that. Apple Developer Program ceremony (Team
     ID-bound certs + provisioning profile registering the
     device's UDID) on a the macOS host mini build host, manual
     `dotnet publish -f net10.0-ios -c Release -r ios-arm64`
     + `xcrun devicectl device install`. Activated the
     `Platforms/iOS/IosSecureEnclaveKeyService.cs` Secure-Enclave
     path that had been written since v0.5+ but never run on
     real hardware.

`Recto.csproj` targets `net10.0-ios` with
`SupportedOSPlatformVersion=15.0`. Bundle ID is
`app.recto.phone`; APNs entitlement is wired in
`Platforms/iOS/Entitlements.plist`. Setup runbook in
`docs/macos-setup.md` (Part A: zero the macOS host setup needed, just trigger
the workflow; Part B: iOS deploy ceremony).

**Lesson banked from the self-hosted runner false-start:** never
put a self-hosted GitHub Actions runner on a public repo without
explicit fork-PR mitigations (`pull_request_target` removed, fork
PRs gated behind manual approval, ideally the runner is
ephemeral / containerized). Default to GitHub-hosted runners for
public-repo CI; reach for self-hosted only when a private repo
(different threat model) or when the test genuinely requires
unique hardware unavailable to GitHub-hosted (e.g., iOS device
deploy with a connected iPhone).

### the test device smoke tests — first real-hardware validation (2026-04-29)

First time the v0.5+ iOS Secure-Enclave code paths ran against
real hardware. Test device was an the test device running iOS 17.x
(original plan was a legacy iPhone capped at iOS 15.x; pivoted to
the test device when that turned out to be the available unit).
`SupportedOSPlatformVersion=15.0` continues to work — the iOS-17
device is well above the floor.

**Secure Enclave path active.** Pairing screen reported
`signing algorithm: ecdsa-p256`, confirming the iOS
`IosSecureEnclaveKeyService` (P-256 keypair via
`kSecAttrTokenIDSecureEnclave`, ACL =
`BiometryCurrentSet | PrivateKeyUsage`, DER-to-raw signature
conversion) was driving — NOT the cross-platform software
fallback.

**All five coin families approved end-to-end:** ed25519 envelope
(single_sign), secp256k1 + EIP-191 (ETH personal sign),
secp256k1 + BIP-137 (BTC + LTC + DOGE + BCH message sign). Each
approval round-tripped through the comms layer back to the mock
bootloader, which recovered the signer address and reported ✓.

**Dark vault UI rendered correctly on iOS WKWebView.** The
IDENTITY & ACCESS / CRYPTO TOKENS section split, per-coin
color-coded badges, and slim 2.75rem topbar all held up; no
platform-specific layout regressions.

Architectural bet validated: phone-resident vault, agent-cap
delegation by JWT, Secure Enclave as root of trust, one BIP-39
mnemonic deriving five coin trees. Real-iPhone deploy validation
gate closed; Wave 8 unblocked.

TLS path validation deferred — cleartext smoke tests proved every
signature path works end-to-end against the LAN-bound mock
bootloader (`NSAllowsLocalNetworking` exempts the local LAN range from ATS).
Mock-self-signed-cert TLS adds cert-trust-on-iPhone friction
without exercising any new crypto code; real TLS validation lands
when Recto deploys behind a real Cloudflare Tunnel cert (already
trusted by iOS).

### Bitcoin credential kind (3 waves, 2026-04-29)

Sister implementation of the Ethereum credential kind. Reuses the
BIP-39 mnemonic + BIP-32 + secp256k1 infrastructure; net-new code
is bech32 encoding (BIP-173), HASH160 + RIPEMD-160, BIP-137
signed-message hashing, BIP-137 compact-signature parse + recover.

**Architecture**: one BIP-39 mnemonic per phone (shared
SecureStorage entry between `MauiEthSignService` and
`MauiBtcSignService`), two BIP-44 trees:
- ETH: `m/44'/60'/0'/0/N` → Ethereum addresses (last 20 bytes of
  Keccak of uncompressed pubkey)
- BTC: `m/84'/0'/0'/0/N` → bech32 P2WPKH addresses
  (`bc1q...` mainnet, `tb1q...` testnet)

One backup ceremony covers both coins. Operator writes down 24
words once, can recover both address trees on any other BIP-39 /
BIP-44 wallet (MetaMask for ETH, Bitcoin Core / Electrum / Sparrow
for BTC, hardware wallets for both).

**Wave 1**: `recto.bitcoin` Python module (RIPEMD-160 from-scratch
reference impl, HASH160, double-SHA-256, bech32/bech32m, BIP-137
hash, P2WPKH/P2PKH/P2SH-P2WPKH address derivation, BIP-137
compact-sig parse + recover), `recto[bitcoin]` extra (empty),
protocol DTOs in `Recto.Shared.Protocol.V04` (BtcSign kind,
BtcMessageKind discriminator, six btc_* context fields,
BtcSignatureBase64 on RespondRequest), `docs/v0.4-protocol.md`
"Bitcoin signing capability (v0.5+)" section. 42 new tests in
`tests/test_bitcoin.py` against canonical BIP-173 + RIPEMD-160 +
BIP-137 reference vectors.

**Wave 2**: `PendingRequest.new_btc(...)` constructor with
construction-time validation, `_pending_to_wire` emits btc_*
fields, `_handle_respond` structure-checks
`btc_signature_base64` (65-byte decode + BIP-137 header byte
27..42), `_notify_resolved` forwards through. Mock bootloader
"Queue BTC message_sign" operator-UI button + best-effort
recovered-address display. New `tests/test_bootloader_btc.py`.

**Wave 3**: `IBtcSignService` interface + `BtcAccount` value
object + `BtcSigningOps` static class (BouncyCastle math) in
`Recto.Shared/Services/`. `MauiBtcSignService` SecureStorage-
backed orchestrator in `Recto/Services/` reading the SAME
mnemonic entry as MauiEthSignService. DI registration alongside
ETH service. Home.razor render arm with orange BTC badge +
ApproveBtcSignAsync dispatcher. ~16 new tests in
`Recto.Shared.Tests/BtcSigningOpsTests.cs` + `Bip32BtcTests.cs`
including BIP-84 reference vector (abandon...about →
bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu) and the
one-mnemonic-two-coins integration test.

**FUSE-mount lag bit hard during this sprint** — bash sandbox
served truncated views of edited files (server.py at 520 lines
mid-line, pyproject.toml at 103 lines mid-section) even after
fresh tmp copies. The Read tool consistently saw the correct
Windows-side state. Validation deferred to the operator's Windows pytest
run; cannot be run from sandbox until FUSE refresh.

---

**Why Bitcoin matters even though Ethereum already shipped**: the
substrate's "phone-resident HD wallet" pitch needs both halves to
land for the cryptocurrency-custody story to be complete. Ethereum
covers the EVM family (mainnet, Base, Optimism, Arbitrum, Polygon,
all the L2s); Bitcoin covers the original chain plus Lightning /
Liquid / sidechains via PSBT-compatible flows. Together they cover
80% of by-market-cap on-chain custody surface. Adding a third token
(e.g. Solana) is small once the second has landed because the
infrastructure pattern is fully proven.

**What carries over from Ethereum (already built, all tested)**:
- `Bip39Wordlist` — canonical 2048-word English wordlist embedded resource
- `Bip39` — mnemonic gen / validation / PBKDF2-HMAC-SHA512 seed derivation
- `Bip32` — master + child derivation, BIP-44 path parser (handles any path)
- `EthSigningOps.SignWithRecovery` — secp256k1 ECDSA with RFC 6979 deterministic-k
  (Bitcoin uses the same curve so this primitive ports directly)
- The phone's BIP-39 mnemonic — Bitcoin derives from the SAME mnemonic at a
  different BIP-44 path. One mnemonic, two coin trees, recoverable on every
  BIP-39 wallet.

**What's NEW for Bitcoin**:
- **BIP-44 path**: `m/84'/0'/0'/0/N` for native SegWit (P2WPKH) — the modern
  default. Optionally support `m/49'/0'/0'/0/N` (nested SegWit P2SH-P2WPKH)
  and `m/44'/0'/0'/0/N` (legacy P2PKH) for compat with older wallets.
- **Address encoding**: bech32 / bech32m for native SegWit (BIP-173 / BIP-350),
  Base58Check for legacy. ~150 LOC of pure-stdlib encoding.
- **PSBT (BIP-174)**: Bitcoin transaction signing isn't a one-shot like
  EIP-191 — it's a multi-step protocol where partial signatures get
  combined. Phone receives a PSBT, signs the inputs it controls, returns
  the partially-signed PSBT. ~400 LOC, plus a verify-side parser. Most
  complex piece of the Bitcoin sprint.
- **Bitcoin message signing (legacy)**: `\x18Bitcoin Signed Message:\n` +
  varint length + message, then double-SHA-256, then signed with secp256k1.
  Different from EIP-191 in two ways: prefix magic byte (0x18 not 0x19)
  and double-SHA-256 instead of Keccak-256. Trivial port from `EthSigningOps`.

**Sprint plan for tomorrow (parallel structure to ETH waves):**

1. **Wave 1 — Python verifier + protocol DTOs.** `recto.bitcoin` module
   (bech32 encoding, double-SHA-256, secp256k1 verify reuses the existing
   pure-stdlib code, address derivation from pubkey via HASH160). New
   `BtcSign` PendingRequest kind, `BtcMessageKind` discriminator
   (`message_signing` / `psbt`), `eth_*`-style context fields renamed
   `btc_*`. Protocol RFC section in `docs/v0.4-protocol.md`. Tests
   against canonical bech32 / Bitcoin signed-message vectors.

2. **Wave 2 — Bootloader handler + mock parity.** Same shape as ETH
   wave 2: `PendingRequest.new_btc(...)`, `_pending_to_wire` emits
   `btc_*` fields, `_handle_respond` accepts `btc_signature_*` and
   forwards through. Mock bootloader gets a "Queue BTC sign" button.

3. **Wave 3 + 4 collapsed — phone-side service + Home.razor approval.**
   `IBtcSignService` in Recto.Shared (interface mirrors `IEthSignService`),
   `MauiBtcSignService` in Recto/Services/ using SAME mnemonic as ETH
   under a NEW BIP-44 path tree. `BtcSigningOps` (or extend
   `EthSigningOps` to share the secp256k1 primitive). Home.razor render
   arm + dispatcher. Single deploy + test cycle since waves 3-4
   collapse for ETH already proved the deploy/test discipline works.

Estimated complexity: ~50% of the ETH sprint since most of the
infrastructure is reusable. Most net-new code is the bech32 encoder
and the PSBT parser/signer. PSBT can ship as `message_signing` first
(Bitcoin signed-message verb, smaller scope than transactions) with
PSBT as a follow-up if it stretches the session.

### Ethereum credential kind (4 waves, 2026-04-28; cross-wallet interop confirmed)

Recto's existing credential kinds (TOTP, WebAuthn, JWT capability,
PKCS#11, PGP) covered human-authentication and traditional-crypto
ground but didn't hold cryptocurrency-style private keys. The
Ethereum sprint added the first half of the cryptocurrency story —
the EVM family. Bitcoin (next session) covers the other half.

**Sprint scope (shipped end-to-end 2026-04-28):**

Ethereum private-key credential kind. BIP39 mnemonic gen +
BIP32/BIP44 derivation at `m/44'/60'/0'/0/0`, EIP-191 personal_sign
end-to-end, public-key + address derivation, sign-then-recover
internal-consistency test + Trezor reference vector cross-wallet
interop test passing. Cross-wallet verified live in MyCrypto +
Python `recto.ethereum.recover_address`. Live phone build
(Windows MAUI Blazor) approved real signatures over TLS-pinned
HTTPS.

**Still ahead (follow-ups, non-blocking; tracked here to surface
on read-pass when revisited):**

- **ImportMnemonicAsync UI** — Settings page hookup so operators
  can paste an existing mnemonic (e.g. from a Ledger recovery
  phrase) and have Recto re-derive the same addresses. Capability
  is in `IEthSignService`; just needs the UI form + biometric gate
  + destructive-confirmation modal.
- **ExportMnemonicAsync UI** — biometric-gated mnemonic display
  for backup ceremony. One-time-display semantics: operator
  confirms they wrote down the words by re-entering 3 of them at
  random positions; mnemonic returns to hidden state after that.
- **Multi-account picker in Settings** — derive accounts at
  `m/44'/60'/0'/0/N` for N=1,2,3... with operator-named labels.
  Today Home.razor only exposes the default account.
- **EIP-712 typed-data + RLP transaction signing**. Today only
  `personal_sign` is wired end-to-end on the phone; `typed_data`
  and `transaction` short-circuit with "not yet implemented". EIP-712
  is structured-hash code (~200 LOC); transaction is RLP encoding
  + EIP-1559 / 2930 / legacy decoders (~300 LOC).
- **Launcher-side bootloader-spawn integration**: when
  `service.yaml` has a `spec.secrets[].source: enclave` with
  `kind: eth_sign`, the launcher should construct + queue an ETH
  PendingRequest via `state.add_pending(...)` rather than the
  existing single_sign path. Today the only callers are the mock
  bootloader and tests.
- **Capability-JWT scope semantics for agent signing**: extend
  `CapabilityJwtClaims` so an `agent:<id>` bearer JWT can authorize
  a single ETH signing operation bounded by target contract,
  method selector, value cap, gas cap, expiry — enforced
  server-side before the digest is produced. Foundation for
  agent-driven signing flows in any consumer with on-chain
  authority requirements.
- **Real-device deploy validation on Apple hardware**. Software
  impl works on any MAUI target so this is "deploy and confirm"
  rather than net-new code. Gated on Apple-platform build host
  availability + Xcode / iOS-version DeviceSupport pairing
  decisions (see phone/CLAUDE.md gotchas).

**Architectural pattern these extend** (already proven by TOTP /
WebAuthn / JWT credential kinds — see Hard Rule #9): the operator's
phone is the unconditional root of trust. Agents access wallet-
signing capabilities only via operator-issued, scoped, time-bounded
JWT capabilities. The agent never gets the raw private key; it
gets a capability that authorizes a single signing operation
within bounds the operator approved on the phone-side. This is
the model that lets a consumer's agent runtime safely sign
on-chain actions on behalf of a human user: each agent
invocation = one signing request to Recto = one operator-pre-
authorized capability draw. The capability's scope (target
contract, method selector, value cap, gas cap, expiry) is
declared at issuance time and enforced server-side before the
private-key material is unwrapped.

**Sprint deliverables (parallels prior credential-kind sprints):**

- New `eth_sign` and `btc_sign` PendingRequest kinds in the
  protocol RFC.
- IBootloaderClient extensions for the new kinds.
- Mock bootloader handlers for both kinds (test vectors from
  EIP-191/712 specs and BIP-174 specs).
- Phone-side service (IEthSignService / IBtcSignService) with
  MAUI implementations.
- Home.razor handlers for the two new kinds, displaying the
  signing context to the operator (which message / which TX) and
  capturing per-call approval.
- Unit tests covering signing test vectors, mnemonic round-trip,
  derivation correctness.

**CLI gap to fill alongside** (caught during a consumer's
auth-rotation pass 2026-04-28; LANDED 2026-04-28): `recto secrets
set <service> <name>` and `recto secrets delete <service> <name>`
ship as backend-agnostic counterparts to the existing
`recto credman set/delete`. Default backend is `dpapi-machine`
because that's the production default for `LocalSystem`-running
services. Mirrors the CredMan command's safety guards (empty-prompt
refusal, hidden input). 13 new CLI tests cover happy paths plus
readonly-backend / unknown-backend / empty-value edge cases.

**ETH groundwork landed 2026-04-28 (first wave)**: `recto.ethereum`
module (pure-stdlib Keccak-256 + EIP-191 hashing + secp256k1 ECDSA
verify + public-key recovery + EIP-55 checksum addresses; 22 new
tests against canonical vectors); new `recto[ethereum]` extra
(intentionally empty — adds no packages); protocol DTO additions in
`Recto.Shared.Protocol.V04` (new `EthSign` kind, `EthMessageKind`
discriminator, ETH-specific context fields, `EthSignatureRsv` on
`RespondRequest`); `docs/v0.4-protocol.md` "Ethereum signing
capability (v0.5+)" section authored.

**Bootloader-side wiring + mock parity landed 2026-04-28 (second
wave)**: `PendingRequest.new_eth(...)` constructor + 7 optional
ETH context fields on the dataclass with construction-time
validation (kind / per-kind body field / address shape);
`recto.bootloader.server`'s `_pending_to_wire` emits the ETH
fields when `kind == "eth_sign"` (omitted for non-ETH kinds —
regression-tested); `_handle_respond` extracts and structure-checks
`eth_signature_rsv` on approvals and forwards through
`_notify_resolved` alongside the existing Ed25519 envelope; mock
bootloader (`phone/RectoMAUIBlazor/dev-tools/mock-bootloader.py`)
gains an "ETH personal_sign" operator-UI button that queues an
EIP-191 login-style message on Base (chain 8453) at
`m/44'/60'/0'/0/0` and recovers + displays the signer address
when the mock is launched from a Recto checkout; 23 new tests in
`tests/test_bootloader_eth.py` covering construction validation,
state persistence round-trip, and live-HTTP end-to-end (good
Ed25519 + good rsv → ok; denied; missing rsv; malformed rsv;
forged Ed25519; non-eth single_sign regression).

**BIP-39 mnemonic + BIP-32/BIP-44 derivation landed 2026-04-28
(fourth wave)**: `eth_derivation_path` promoted from advisory
metadata to a real lookup parameter — phone now stores a 24-word
BIP-39 mnemonic per alias and derives infinitely many addresses
on demand. `Bip39Wordlist` (canonical 2048-word wordlist as
embedded resource), `Bip39` (mnemonic gen + validation + seed
derivation via PBKDF2-HMAC-SHA512), `Bip32` (master + child
derivation, BIP-44 path parser) all in `Recto.Shared/Services/`.
`MauiEthSignService` rewritten to mnemonic-only storage with
in-memory derivation per sign + ZeroMemory wipe of all
intermediates. Mnemonics interoperable with every other BIP-39
wallet (MetaMask, Ledger, Trezor) — Trezor reference vector
("abandon ... about" → m/44'/60'/0'/0/0 →
0x9858EfFD232B4033E47d90003D41EC34EcaEda94) confirmed by unit
test. ~30 new tests in `Recto.Shared.Tests/`. Home.razor approval
card now shows the derived address inline so operators see which
account will sign before approving. Crypto classes moved from
`Recto/Services/` to `Recto.Shared/Services/` (with BouncyCastle +
wordlist resource) so the test project can reach them via the
existing project reference. **Breaking change**: v0.5+ first-cut
testers' single-key SecureStorage entries are no longer read by
any wave-4 code path; first wave-4 sign generates a fresh
mnemonic + new address tree. Cleared via `ClearAsync` (which
cleans up both new mnemonic + legacy single-key entries).

**Phone-side signing + Home.razor approval UI landed 2026-04-28
(third wave)**: `IEthSignService` interface in
`Recto.Shared/Services/` (cross-platform contract:
EnsureMnemonic / GetAccount / Exists / SignPersonalSign /
Clear); `EthAccount(DerivationPath, Address)` value object in
`Recto.Shared/Models/`; `EthSigningOps` static class in
`Recto/Services/` (pure BouncyCastle math: secp256k1 keygen,
public-key + address derivation, Keccak-256, EIP-191 hash,
RFC 6979 deterministic-k ECDSA sign with low-s canonicalization
+ v-recovery, SEC1 §4.1.6 public-key recovery for v-recovery's
own use); `MauiEthSignService` SecureStorage-backed
orchestrator in `Recto/Services/` (one secp256k1 keypair per
alias under storage key `recto.phone.eth.{alias}`,
implicit-create-on-use); DI registration as a single
cross-platform singleton in `MauiProgram.cs` (no `#if IOS /
ANDROID` fan-out since neither Secure Enclave nor StrongBox
support secp256k1 — the software impl IS the correct long-term
implementation, not a fallback); Home.razor render arm
displaying chain id (mainnet / Base / Sepolia / Polygon /
Optimism / Arbitrum / Base Sepolia named, "chain N" otherwise) +
derivation path + message text + ApproveEthSignAsync dispatcher
producing the dual signature (secp256k1 rsv via IEthSignService
+ Ed25519 envelope via IEnclaveKeyService) and forwarding both
via RespondRequest. v0.5+ scope: NO BIP39 mnemonic, NO BIP32/BIP44
derivation — `eth_derivation_path` field is advisory metadata;
single key per alias regardless of path. Mock bootloader
placeholder-address suppression so test queues with
`0x` + `00`*20 as the expected address don't flag amber
"differs from expected" on every successful round-trip.

The protocol + Python launcher / verifier + mock bootloader +
Windows-MAUI phone path are a complete loop. End-to-end demo:
Queue ETH personal_sign (mock UI) → Approve (phone) → secp256k1
sign + Ed25519 envelope → mock recovers signer address from rsv
→ operator UI shows "recovered: 0x..." inline. Live tested
2026-04-28 with cross-wallet interop confirmed via MyCrypto +
Python `recto.ethereum.recover_address` against multiple
sequential signatures.

Major-token-credential-kinds sprint exits fully when Bitcoin
also lands (next session). After that, downstream consumers can
begin binding user wallets to platform identities and rotating
any on-chain authority roles (e.g. minter / signer keys) onto
Recto-custodied addresses.
