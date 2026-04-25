"""Command-line interface for Recto.

Subcommands:
    recto launch <yaml>                       - run the supervised child
    recto credman set <service> <name>        - install a secret in
                                                Windows Credential Manager
                                                (interactive prompt)
    recto credman list <service>              - list installed secret names
                                                for a service
    recto credman delete <service> <name>     - remove an installed secret
    recto status <service>                    - report NSSM service state
    recto migrate-from-nssm <service>         - read NSSM config, generate
                                                YAML, import secrets to
                                                credman, retarget AppPath,
                                                clear AppEnvironmentExtra

The CLI is a thin dispatcher. Each subcommand handler delegates to one
of `recto.launcher`, `recto.secrets.credman`, `recto.config`, or
`recto.nssm`. This keeps argparse-related code together and the
domain modules independent.

Testability seam:
    Every external dependency that touches a real system - subprocess.run
    for NSSM, getpass.getpass for secret prompts, Windows Credential
    Manager for write/list/delete - is reachable through a constructor
    arg or factory parameter. tests/test_cli.py wires stubs in.

`python -m recto` is the operator-facing invocation and is wired in
`recto/__main__.py`. The `recto = "recto.cli:main"` console-script
entry in `pyproject.toml` exposes the same `main()`.
"""

from __future__ import annotations

import argparse
import getpass
import json
import sys
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any, TextIO

from recto.config import (
    ConfigValidationError,
    ServiceConfig,
    load_config,
)
from recto.nssm import (
    NssmClient,
    NssmConfig,
    NssmError,
    NssmNotInstalledError,
    NssmServiceNotFoundError,
    NssmStatus,
    split_environment_extra,
)
from recto.secrets import (
    CredManSource,
    SecretNotFoundError,
    SecretSourceError,
)

__all__ = [
    "CredManFactory",
    "NssmFactory",
    "build_parser",
    "main",
]


# ---------------------------------------------------------------------------
# Factory aliases (so tests can inject stubs without subclassing argparse)
# ---------------------------------------------------------------------------


CredManFactory = Callable[[str], CredManSource]
"""(service_name) -> CredManSource. Production uses CredManSource(service);
tests pass a factory that returns a FakeCredManSource backed by a dict."""


NssmFactory = Callable[[], NssmClient]
"""() -> NssmClient. Production uses NssmClient(); tests pass a factory
that returns one with a stub runner."""


PromptFn = Callable[[str], str]
"""(prompt) -> value. Production uses getpass.getpass; tests pass a fake."""


LaunchFn = Callable[..., int]
"""(config, **kwargs) -> exit_code. Wraps recto.launcher.run so tests
can verify the CLI dispatches correctly without spawning a child."""


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    """Build the top-level argparse parser with all subcommands wired."""
    parser = argparse.ArgumentParser(
        prog="recto",
        description=(
            "Modern Windows-service wrapper. Spiritual successor to NSSM. "
            "See https://github.com/darwincommits/Recto."
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=_version_string(),
    )

    sub = parser.add_subparsers(
        dest="command",
        title="subcommands",
        required=True,
        metavar="{launch,credman,status,migrate-from-nssm}",
    )

    # launch ---------------------------------------------------------------
    p_launch = sub.add_parser(
        "launch",
        help="Run a supervised child from a service.yaml.",
        description=(
            "Read service.yaml, fetch declared secrets, spawn the child "
            "process, and supervise its lifecycle (restart policy + "
            "healthz probe + webhook events). This is the entry point "
            "NSSM (or systemd / launchd in v0.3+) points at."
        ),
    )
    p_launch.add_argument("yaml_path", help="Path to service.yaml")
    p_launch.add_argument(
        "--once",
        action="store_true",
        help="Single-spawn debug mode: do NOT loop on restart policy.",
    )

    # credman --------------------------------------------------------------
    p_credman = sub.add_parser(
        "credman",
        help="Manage Windows Credential Manager entries scoped to a service.",
        description=(
            "Install, list, or remove secret values stored in Windows "
            "Credential Manager under the 'recto:{service}:{name}' "
            "target-name convention. Values are DPAPI-encrypted at rest."
        ),
    )
    sub_credman = p_credman.add_subparsers(
        dest="credman_command",
        required=True,
        metavar="{set,list,delete}",
    )

    p_credman_set = sub_credman.add_parser(
        "set",
        help="Install (or replace) a secret value.",
        description=(
            "Prompt for a secret value and store it under "
            "recto:{service}:{name}. Existing entries are replaced. The "
            "value is read with getpass; nothing is echoed to the "
            "terminal and the value never appears on the command line."
        ),
    )
    p_credman_set.add_argument("service", help="Logical service name")
    p_credman_set.add_argument("name", help="Secret name (e.g. MY_API_KEY)")
    p_credman_set.add_argument(
        "--value",
        help=(
            "Pass the value directly instead of prompting. ONLY for "
            "scripted / migration paths; you almost always want the "
            "interactive prompt instead."
        ),
    )

    p_credman_list = sub_credman.add_parser(
        "list",
        help="List secret names installed for a service.",
        description=(
            "Print one secret name per line, sorted. Values are never "
            "displayed - this is the inventory view."
        ),
    )
    p_credman_list.add_argument("service", help="Logical service name")

    p_credman_delete = sub_credman.add_parser(
        "delete",
        help="Remove an installed secret.",
        description=(
            "Delete the credential at recto:{service}:{name}. Errors if "
            "the credential does not exist."
        ),
    )
    p_credman_delete.add_argument("service", help="Logical service name")
    p_credman_delete.add_argument("name", help="Secret name")

    # status ---------------------------------------------------------------
    p_status = sub.add_parser(
        "status",
        help="Report the NSSM service state for the named service.",
        description=(
            "Shell out to `nssm status <service>` and print the result. "
            "Exit code 0 if the service is RUNNING, 1 otherwise. "
            "Useful as a poll target from a monitoring loop."
        ),
    )
    p_status.add_argument("service", help="NSSM service name")

    # migrate-from-nssm ----------------------------------------------------
    p_migrate = sub.add_parser(
        "migrate-from-nssm",
        help="Migrate an existing NSSM service to Recto-managed config.",
        description=(
            "Read the named NSSM service's config, generate an equivalent "
            "service.yaml, install AppEnvironmentExtra entries into "
            "Credential Manager, retarget AppPath at `python -m recto "
            "launch <yaml>`, and clear AppEnvironmentExtra. Idempotent: "
            "already-migrated services produce no-ops on subsequent runs."
        ),
    )
    p_migrate.add_argument("service", help="NSSM service name to migrate")
    p_migrate.add_argument(
        "--yaml-out",
        help=(
            "Path to write the generated service.yaml. Default: "
            "<service>.service.yaml in the current directory."
        ),
    )
    p_migrate.add_argument(
        "--python-exe",
        default="python.exe",
        help=(
            "Path to the python.exe that NSSM should call. Default: "
            "python.exe (resolved via PATH at service-start time)."
        ),
    )
    p_migrate.add_argument(
        "--dry-run",
        action="store_true",
        help=(
            "Read NSSM config, print the plan, but make NO changes. "
            "Use this first to verify what migrate-from-nssm WOULD do."
        ),
    )

    return parser


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main(
    argv: Sequence[str] | None = None,
    *,
    credman_factory: CredManFactory | None = None,
    nssm_factory: NssmFactory | None = None,
    prompt: PromptFn = getpass.getpass,
    launch_fn: LaunchFn | None = None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    """Parse argv, dispatch to the right subcommand handler, return exit code.

    Args:
        argv: Override for sys.argv[1:]. Tests pass an explicit list.
        credman_factory: (service) -> CredManSource. Default builds a real
            CredManSource. Tests inject a FakeCredManSource factory.
        nssm_factory: () -> NssmClient. Default builds a real NssmClient
            with the default subprocess runner. Tests inject a stub.
        prompt: getpass.getpass-shaped callable for credman set. Tests
            pass a deterministic stub.
        launch_fn: recto.launcher.run-shaped callable. Default uses the
            real launcher; tests inject a stub that returns a canned
            exit code.
        stdout, stderr: Output streams. Default sys.stdout / sys.stderr.

    Returns:
        Process exit code. 0 = success, non-zero = error.
    """
    out: TextIO = stdout if stdout is not None else sys.stdout
    err: TextIO = stderr if stderr is not None else sys.stderr

    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        # argparse calls sys.exit(2) on parse errors; preserve that code.
        return int(exc.code) if exc.code is not None else 0

    # Dispatch table - keyed on (command, credman_subcommand).
    cmd: str = args.command
    try:
        if cmd == "launch":
            return _cmd_launch(args, launch_fn=launch_fn, out=out, err=err)
        if cmd == "credman":
            sub = args.credman_command
            cred = (credman_factory or _default_credman_factory)(args.service)
            if sub == "set":
                return _cmd_credman_set(
                    args, cred=cred, prompt=prompt, out=out, err=err
                )
            if sub == "list":
                return _cmd_credman_list(args, cred=cred, out=out, err=err)
            if sub == "delete":
                return _cmd_credman_delete(args, cred=cred, out=out, err=err)
            print(f"recto credman: unknown subcommand {sub!r}", file=err)
            return 2
        if cmd == "status":
            nssm = (nssm_factory or _default_nssm_factory)()
            return _cmd_status(args, nssm=nssm, out=out, err=err)
        if cmd == "migrate-from-nssm":
            nssm = (nssm_factory or _default_nssm_factory)()
            cred = (credman_factory or _default_credman_factory)(args.service)
            return _cmd_migrate_from_nssm(
                args, nssm=nssm, cred=cred, out=out, err=err
            )
    except KeyboardInterrupt:
        print("\nrecto: interrupted", file=err)
        return 130

    print(f"recto: unknown command {cmd!r}", file=err)
    return 2


# ---------------------------------------------------------------------------
# Default factories - lazily build real Credential Manager and NSSM clients
# ---------------------------------------------------------------------------


def _default_credman_factory(service: str) -> CredManSource:
    return CredManSource(service)


def _default_nssm_factory() -> NssmClient:
    return NssmClient()


# ---------------------------------------------------------------------------
# Subcommand handlers
# ---------------------------------------------------------------------------


def _cmd_launch(
    args: argparse.Namespace,
    *,
    launch_fn: LaunchFn | None,
    out: TextIO,
    err: TextIO,
) -> int:
    """Handle `recto launch <yaml>`.

    Loads and validates the YAML, then calls recto.launcher.run (or
    the injected launch_fn). Returns the launcher's exit code, or 1
    if the YAML failed to load.
    """
    yaml_path = Path(args.yaml_path)
    try:
        config: ServiceConfig = load_config(yaml_path)
    except ConfigValidationError as exc:
        print(f"recto launch: invalid config: {exc}", file=err)
        return 1
    except FileNotFoundError:
        print(f"recto launch: file not found: {yaml_path}", file=err)
        return 1

    # Lazy import to avoid pulling subprocess + threading at parse time.
    if launch_fn is None:
        from recto.launcher import launch as _launch_once
        from recto.launcher import run as _launch_run

        launch_fn = _launch_once if args.once else _launch_run
    rc = launch_fn(config)
    return int(rc)


def _cmd_credman_set(
    args: argparse.Namespace,
    *,
    cred: CredManSource,
    prompt: PromptFn,
    out: TextIO,
    err: TextIO,
) -> int:
    """Handle `recto credman set <service> <name> [--value VALUE]`.

    Without --value: prompts for the secret value via getpass (no echo).
    With --value: takes the value from the flag (scripted-only path).

    Confirmation prompt is intentionally NOT included here - the operator
    can verify the install via `recto credman list <service>`.
    """
    service: str = args.service
    name: str = args.name
    value: str
    if args.value is not None:
        value = args.value
    else:
        value = prompt(f"Value for recto:{service}:{name} (input hidden): ")
        if not value:
            print(
                "recto credman set: refusing to install empty value; "
                "use --value '' if you really mean it",
                file=err,
            )
            return 1
    try:
        cred.write(name, value)
    except SecretSourceError as exc:
        print(f"recto credman set: {exc}", file=err)
        return 1
    print(f"installed recto:{service}:{name}", file=out)
    return 0


def _cmd_credman_list(
    args: argparse.Namespace,
    *,
    cred: CredManSource,
    out: TextIO,
    err: TextIO,
) -> int:
    """Handle `recto credman list <service>`.

    Prints one name per line. Empty list means the service has no
    Recto-installed secrets; we exit 0 either way (empty inventory is
    not an error).
    """
    try:
        names = cred.list_names()
    except SecretSourceError as exc:
        print(f"recto credman list: {exc}", file=err)
        return 1
    for n in names:
        print(n, file=out)
    return 0


def _cmd_credman_delete(
    args: argparse.Namespace,
    *,
    cred: CredManSource,
    out: TextIO,
    err: TextIO,
) -> int:
    """Handle `recto credman delete <service> <name>`."""
    name: str = args.name
    service: str = args.service
    try:
        cred.delete(name)
    except SecretNotFoundError:
        print(
            f"recto credman delete: recto:{service}:{name} does not exist",
            file=err,
        )
        return 1
    except SecretSourceError as exc:
        print(f"recto credman delete: {exc}", file=err)
        return 1
    print(f"deleted recto:{service}:{name}", file=out)
    return 0


def _cmd_status(
    args: argparse.Namespace,
    *,
    nssm: NssmClient,
    out: TextIO,
    err: TextIO,
) -> int:
    """Handle `recto status <service>`.

    Exit code: 0 if SERVICE_RUNNING, 1 otherwise. Body is the raw
    status string from `nssm status`.
    """
    service: str = args.service
    try:
        status = nssm.status(service)
    except NssmNotInstalledError as exc:
        print(f"recto status: {exc}", file=err)
        return 1
    except NssmError as exc:
        print(f"recto status: {exc}", file=err)
        return 1
    print(status, file=out)
    return 0 if status == NssmStatus.SERVICE_RUNNING else 1


def _cmd_migrate_from_nssm(
    args: argparse.Namespace,
    *,
    nssm: NssmClient,
    cred: CredManSource,
    out: TextIO,
    err: TextIO,
) -> int:
    """Handle `recto migrate-from-nssm <service>`.

    Steps:
        1. Read existing NSSM config via `nssm get`.
        2. For each AppEnvironmentExtra entry: install in Credential
           Manager under recto:{service}:{key}.
        3. Generate a service.yaml with a `secrets:` block referencing
           those credman targets.
        4. Retarget NSSM AppPath at `python -m recto launch <yaml>`,
           AppParameters at the YAML path, and reset
           AppEnvironmentExtra so the plaintext entries are gone.

    --dry-run skips steps 2-4 and prints the plan instead.

    Idempotent: re-running on an already-migrated service is a no-op
    on the credman side (CredWriteW upserts) and a same-value write
    on NSSM (AppPath already points where we'd point it).
    """
    service: str = args.service
    yaml_out_path = Path(
        args.yaml_out if args.yaml_out else f"{service}.service.yaml"
    )
    python_exe: str = args.python_exe
    dry_run: bool = bool(args.dry_run)

    try:
        nssm_cfg = nssm.get_all(service)
    except NssmServiceNotFoundError:
        print(
            f"recto migrate-from-nssm: NSSM service {service!r} not found",
            file=err,
        )
        return 1
    except NssmNotInstalledError as exc:
        print(f"recto migrate-from-nssm: {exc}", file=err)
        return 1
    except NssmError as exc:
        print(f"recto migrate-from-nssm: {exc}", file=err)
        return 1

    secrets = list(split_environment_extra(
        "\n".join(nssm_cfg.app_environment_extra)
    ))

    plan = _migration_plan(
        nssm_cfg=nssm_cfg,
        secrets=secrets,
        yaml_out=yaml_out_path,
        python_exe=python_exe,
    )
    print(json.dumps(plan, indent=2, default=str), file=out)
    if dry_run:
        print(
            "recto migrate-from-nssm: --dry-run; no changes made",
            file=out,
        )
        return 0

    # Apply.
    try:
        for key, value in secrets:
            cred.write(key, value, comment=f"Migrated from NSSM:{service}")
        yaml_text = _generate_service_yaml(
            service=service,
            nssm_cfg=nssm_cfg,
            secret_keys=[k for k, _ in secrets],
        )
        yaml_out_path.write_text(yaml_text, encoding="utf-8")
        # Retarget NSSM. AppPath is now python.exe; AppParameters is
        # `-m recto launch <yaml>`. AppEnvironmentExtra clears.
        nssm.set(service, "AppPath", python_exe)
        nssm.set(
            service,
            "AppParameters",
            f"-m recto launch {yaml_out_path}",
        )
        nssm.reset(service, "AppEnvironmentExtra")
    except (SecretSourceError, NssmError, OSError) as exc:
        print(f"recto migrate-from-nssm: apply failed: {exc}", file=err)
        return 1
    print(
        f"recto migrate-from-nssm: migrated {service!r}; "
        f"yaml at {yaml_out_path}; "
        f"installed {len(secrets)} secret(s); "
        f"NSSM AppEnvironmentExtra cleared.",
        file=out,
    )
    return 0


# ---------------------------------------------------------------------------
# Migration helpers
# ---------------------------------------------------------------------------


def _migration_plan(
    *,
    nssm_cfg: NssmConfig,
    secrets: list[tuple[str, str]],
    yaml_out: Path,
    python_exe: str,
) -> dict[str, Any]:
    """Build a dict describing what migrate-from-nssm WOULD do.

    Secret VALUES are masked (replaced with '<redacted>') so the plan
    can be JSON-printed without leaking. Operator should review the
    plan with --dry-run before applying.
    """
    return {
        "service": nssm_cfg.service,
        "current_app_path": nssm_cfg.app_path,
        "current_app_parameters": nssm_cfg.app_parameters,
        "current_app_directory": nssm_cfg.app_directory,
        "current_environment_extra_count": len(secrets),
        "secrets_to_install": [
            {"name": k, "value": "<redacted>"} for k, _ in secrets
        ],
        "yaml_out": str(yaml_out),
        "new_app_path": python_exe,
        "new_app_parameters": f"-m recto launch {yaml_out}",
    }


def _generate_service_yaml(
    *,
    service: str,
    nssm_cfg: NssmConfig,
    secret_keys: list[str],
) -> str:
    """Produce the generated service.yaml text.

    Hand-rolled (not via PyYAML's dump) so we control formatting:
    fields appear in a stable order, comments are preserved, and the
    output is human-reviewable. PyYAML's default style would munge
    quoting on values with `:` or `#` and lose readability.
    """
    lines: list[str] = []
    a = lines.append
    a("# Generated by `recto migrate-from-nssm`.")
    a(f"# Source NSSM service: {nssm_cfg.service}")
    a("# Review and edit before relying on this in production.")
    a("apiVersion: recto/v1")
    a("kind: Service")
    a("metadata:")
    a(f"  name: {service}")
    if nssm_cfg.display_name:
        a(f"  description: \"{_escape_yaml(nssm_cfg.display_name)}\"")
    a("spec:")
    a(f"  exec: \"{_escape_yaml(nssm_cfg.app_path)}\"")
    if nssm_cfg.app_parameters:
        # AppParameters is one string; split into argv-ish words for the
        # YAML's args list. Naive whitespace split is correct for the
        # common case; users with quoted args will have to hand-edit.
        a("  args:")
        for w in nssm_cfg.app_parameters.split():
            a(f"    - \"{_escape_yaml(w)}\"")
    if nssm_cfg.app_directory:
        a(f"  working_dir: \"{_escape_yaml(nssm_cfg.app_directory)}\"")
    if secret_keys:
        a("  secrets:")
        for key in secret_keys:
            a(f"    - name: {key}")
            a("      source: credman")
            a(f"      target_env: {key}")
            a("      required: true")
    a("  restart:")
    a("    policy: always")
    a("    backoff: exponential")
    a("    initial_delay_seconds: 1")
    a("    max_delay_seconds: 60")
    a("    max_attempts: 10")
    a("")
    return "\n".join(lines)


def _escape_yaml(s: str) -> str:
    """Escape backslashes and double-quotes for YAML double-quoted strings.

    We only emit double-quoted scalars in the generated YAML, so the
    only escaping needed is `\\` -> `\\\\` and `"` -> `\\"`. Newlines
    are left as-is; the migrate path doesn't expect multi-line values.
    """
    return s.replace("\\", "\\\\").replace("\"", "\\\"")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _version_string() -> str:
    """Build the --version output string."""
    from recto import __version__

    return f"recto {__version__}"
