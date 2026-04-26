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
    recto apply <yaml>                        - reconcile NSSM state to
                                                match a service.yaml
                                                (GitOps-style diff + apply)
    recto events <yaml>                       - dump the running launcher's
                                                recent lifecycle events from
                                                the admin UI's in-memory
                                                ring buffer

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
from recto._migrate import (
    build_migration_plan,
    generate_service_yaml,
    partition_env_entries,
)
from recto.reconcile import (
    ReconcilePlan,
    apply_plan,
    compute_plan,
    render_plan,
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


CredManFactory = Callable[[str], CredManSource]
NssmFactory = Callable[[], NssmClient]
PromptFn = Callable[[str], str]
ConfirmFn = Callable[[str], str]
LaunchFn = Callable[..., int]


def build_parser() -> argparse.ArgumentParser:
    """Build the top-level argparse parser with all subcommands wired."""
    parser = argparse.ArgumentParser(
        prog="recto",
        description=(
            "Modern Windows-service wrapper. Spiritual successor to NSSM. "
            "See https://github.com/darwincommits/Recto."
        ),
    )
    parser.add_argument("--version", action="version", version=_version_string())
    sub = parser.add_subparsers(
        dest="command",
        title="subcommands",
        required=True,
        metavar="{launch,credman,status,migrate-from-nssm,apply,events}",
    )

    # launch
    p_launch = sub.add_parser("launch", help="Run a supervised child from a service.yaml.")
    p_launch.add_argument("yaml_path", help="Path to service.yaml")
    p_launch.add_argument("--once", action="store_true", help="Single-spawn debug mode.")

    # credman
    p_credman = sub.add_parser("credman", help="Manage Credential Manager entries.")
    sub_credman = p_credman.add_subparsers(
        dest="credman_command", required=True, metavar="{set,list,delete}",
    )
    p_credman_set = sub_credman.add_parser("set", help="Install (or replace) a secret value.")
    p_credman_set.add_argument("service")
    p_credman_set.add_argument("name")
    p_credman_set.add_argument("--value", help="Pass the value directly instead of prompting.")
    p_credman_list = sub_credman.add_parser("list", help="List secret names for a service.")
    p_credman_list.add_argument("service")
    p_credman_delete = sub_credman.add_parser("delete", help="Remove an installed secret.")
    p_credman_delete.add_argument("service")
    p_credman_delete.add_argument("name")

    # status
    p_status = sub.add_parser("status", help="Report NSSM service state.")
    p_status.add_argument("service")

    # migrate-from-nssm
    p_migrate = sub.add_parser(
        "migrate-from-nssm", help="Migrate an existing NSSM service to Recto-managed config."
    )
    p_migrate.add_argument("service")
    p_migrate.add_argument("--yaml-out")
    p_migrate.add_argument("--python-exe", default="python.exe")
    p_migrate.add_argument("--dry-run", action="store_true")
    p_migrate.add_argument(
        "--keep-as-env",
        default="",
        help=(
            "Comma-separated list of AppEnvironmentExtra keys that should "
            "land in the YAML's spec.env: block instead of CredMan. "
            "Default: empty -- every entry treated as a secret."
        ),
    )

    # events
    p_events = sub.add_parser(
        "events", help="Dump the running launcher's recent lifecycle events.",
    )
    p_events.add_argument("yaml_path")
    p_events.add_argument("--kind", default=None)
    p_events.add_argument("--limit", type=int, default=200)
    p_events.add_argument("--restart-history", action="store_true")

    # apply
    p_apply = sub.add_parser(
        "apply", help="Reconcile NSSM service state to match a service.yaml.",
    )
    p_apply.add_argument("yaml_path")
    p_apply.add_argument("--python-exe", default="python.exe")
    p_apply.add_argument("--yes", "-y", action="store_true")
    p_apply.add_argument("--dry-run", action="store_true")

    return parser


def main(
    argv: Sequence[str] | None = None,
    *,
    credman_factory: CredManFactory | None = None,
    nssm_factory: NssmFactory | None = None,
    prompt: PromptFn = getpass.getpass,
    confirm: ConfirmFn = input,
    launch_fn: LaunchFn | None = None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    out: TextIO = stdout if stdout is not None else sys.stdout
    err: TextIO = stderr if stderr is not None else sys.stderr
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return int(exc.code) if exc.code is not None else 0
    cmd: str = args.command
    try:
        if cmd == "launch":
            return _cmd_launch(args, launch_fn=launch_fn, out=out, err=err)
        if cmd == "credman":
            sub = args.credman_command
            cred = (credman_factory or _default_credman_factory)(args.service)
            if sub == "set":
                return _cmd_credman_set(args, cred=cred, prompt=prompt, out=out, err=err)
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
            return _cmd_migrate_from_nssm(args, nssm=nssm, cred=cred, out=out, err=err)
        if cmd == "apply":
            nssm = (nssm_factory or _default_nssm_factory)()
            return _cmd_apply(args, nssm=nssm, confirm=confirm, out=out, err=err)
        if cmd == "events":
            return _cmd_events(args, out=out, err=err)
    except KeyboardInterrupt:
        print("\nrecto: interrupted", file=err)
        return 130
    print(f"recto: unknown command {cmd!r}", file=err)
    return 2


def _default_credman_factory(service: str) -> CredManSource:
    return CredManSource(service)


def _default_nssm_factory() -> NssmClient:
    return NssmClient()


def _cmd_launch(args, *, launch_fn, out, err):
    yaml_path = Path(args.yaml_path)
    try:
        config: ServiceConfig = load_config(yaml_path)
    except ConfigValidationError as exc:
        print(f"recto launch: invalid config: {exc}", file=err)
        return 1
    except FileNotFoundError:
        print(f"recto launch: file not found: {yaml_path}", file=err)
        return 1
    if launch_fn is None:
        from recto.launcher import launch as _launch_once
        from recto.launcher import run as _launch_run
        launch_fn = _launch_once if args.once else _launch_run
    return int(launch_fn(config))


def _cmd_credman_set(args, *, cred, prompt, out, err):
    service, name = args.service, args.name
    if args.value is not None:
        value = args.value
    else:
        value = prompt(f"Value for recto:{service}:{name} (input hidden): ")
        if not value:
            print("recto credman set: refusing to install empty value; use --value '' if you really mean it", file=err)
            return 1
    try:
        cred.write(name, value)
    except SecretSourceError as exc:
        print(f"recto credman set: {exc}", file=err)
        return 1
    print(f"installed recto:{service}:{name}", file=out)
    return 0


def _cmd_credman_list(args, *, cred, out, err):
    try:
        names = cred.list_names()
    except SecretSourceError as exc:
        print(f"recto credman list: {exc}", file=err)
        return 1
    for n in names:
        print(n, file=out)
    return 0


def _cmd_credman_delete(args, *, cred, out, err):
    name, service = args.name, args.service
    try:
        cred.delete(name)
    except SecretNotFoundError:
        print(f"recto credman delete: recto:{service}:{name} does not exist", file=err)
        return 1
    except SecretSourceError as exc:
        print(f"recto credman delete: {exc}", file=err)
        return 1
    print(f"deleted recto:{service}:{name}", file=out)
    return 0


def _cmd_status(args, *, nssm, out, err):
    service = args.service
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


def _cmd_migrate_from_nssm(args, *, nssm, cred, out, err):
    service = args.service
    yaml_out_path = Path(args.yaml_out if args.yaml_out else f"{service}.service.yaml")
    python_exe = args.python_exe
    dry_run = bool(args.dry_run)
    try:
        nssm_cfg = nssm.get_all(service)
    except NssmServiceNotFoundError:
        print(f"recto migrate-from-nssm: NSSM service {service!r} not found", file=err)
        return 1
    except NssmNotInstalledError as exc:
        print(f"recto migrate-from-nssm: {exc}", file=err)
        return 1
    except NssmError as exc:
        print(f"recto migrate-from-nssm: {exc}", file=err)
        return 1
    all_entries = list(split_environment_extra("\n".join(nssm_cfg.app_environment_extra)))
    keep_as_env = (
        [k.strip() for k in args.keep_as_env.split(",") if k.strip()]
        if args.keep_as_env else []
    )
    secrets, plain_env = partition_env_entries(all_entries, keep_as_env=keep_as_env)
    plan = build_migration_plan(
        nssm_cfg=nssm_cfg, secrets=secrets, yaml_out=yaml_out_path,
        python_exe=python_exe, plain_env=plain_env,
    )
    print(json.dumps(plan, indent=2, default=str), file=out)
    if dry_run:
        print("recto migrate-from-nssm: --dry-run; no changes made", file=out)
        return 0
    try:
        for key, value in secrets:
            cred.write(key, value, comment=f"Migrated from NSSM:{service}")
        yaml_text = generate_service_yaml(
            service=service, nssm_cfg=nssm_cfg,
            secret_keys=[k for k, _ in secrets], plain_env=plain_env,
        )
        yaml_out_path.write_text(yaml_text, encoding="utf-8")
        nssm.set(service, "AppPath", python_exe)
        nssm.set(service, "AppParameters", f"-m recto launch {yaml_out_path}")
        nssm.reset(service, "AppEnvironmentExtra")
    except (SecretSourceError, NssmError, OSError) as exc:
        print(f"recto migrate-from-nssm: apply failed: {exc}", file=err)
        return 1
    print(
        f"recto migrate-from-nssm: migrated {service!r}; yaml at {yaml_out_path}; "
        f"installed {len(secrets)} secret(s); NSSM AppEnvironmentExtra cleared.",
        file=out,
    )
    return 0


def _cmd_apply(args, *, nssm, confirm, out, err):
    yaml_path = Path(args.yaml_path).resolve()
    try:
        cfg: ServiceConfig = load_config(yaml_path)
    except ConfigValidationError as exc:
        print(f"recto apply: invalid config: {exc}", file=err)
        return 1
    except FileNotFoundError:
        print(f"recto apply: file not found: {yaml_path}", file=err)
        return 1
    service = cfg.metadata.name
    try:
        current = nssm.get_all(service)
    except NssmServiceNotFoundError:
        print(
            f"recto apply: NSSM service {service!r} not found. "
            f"Either register it first via `nssm install {service}`, "
            f"or use `recto migrate-from-nssm <service>` if you're "
            f"migrating an existing non-Recto service.",
            file=err,
        )
        return 1
    except NssmNotInstalledError as exc:
        print(f"recto apply: {exc}", file=err)
        return 1
    except NssmError as exc:
        print(f"recto apply: {exc}", file=err)
        return 1
    plan: ReconcilePlan = compute_plan(
        cfg, current, yaml_path=yaml_path, python_exe=args.python_exe
    )
    print(render_plan(plan), file=out)
    if plan.is_noop:
        return 0
    if args.dry_run:
        print("recto apply: --dry-run; no changes made", file=out)
        return 0
    if not args.yes:
        try:
            answer = confirm("Apply these changes? (y/N): ")
        except EOFError:
            answer = ""
        if answer.strip().lower() not in ("y", "yes"):
            print("recto apply: aborted (no changes made)", file=out)
            return 0
    try:
        apply_plan(plan, nssm)
    except NssmError as exc:
        print(f"recto apply: apply failed: {exc}", file=err)
        return 1
    summary = f"recto apply: applied {len(plan.changes)} change(s)"
    if plan.clear_environment_extra:
        summary += " + cleared AppEnvironmentExtra"
    summary += "."
    print(summary, file=out)
    return 0


def _cmd_events(args, *, out, err, fetch_url=None):
    """Handle ``recto events <yaml> [--kind K] [--limit N] [--restart-history]``."""
    yaml_path = Path(args.yaml_path)
    try:
        cfg: ServiceConfig = load_config(yaml_path)
    except ConfigValidationError as exc:
        print(f"recto events: invalid config: {exc}", file=err)
        return 1
    except FileNotFoundError:
        print(f"recto events: file not found: {yaml_path}", file=err)
        return 1
    if not cfg.spec.admin_ui.enabled:
        print(
            "recto events: spec.admin_ui.enabled is false in this YAML "
            "-- the launcher isn't running an admin UI to query. "
            "Check NSSM's AppStdout log file for the JSON event stream.",
            file=err,
        )
        return 1
    bind = cfg.spec.admin_ui.bind or "127.0.0.1:5050"
    endpoint = "restart-history" if args.restart_history else "events"
    url = f"http://{bind}/api/{endpoint}?limit={int(args.limit)}"
    if args.kind:
        from urllib.parse import quote
        for k in args.kind.split(","):
            k = k.strip()
            if k:
                url += f"&kind={quote(k)}"
    if fetch_url is None:
        fetch_url = _default_fetch_url
    try:
        body = fetch_url(url, 5.0)
    except Exception as exc:  # noqa: BLE001
        print(
            f"recto events: failed to reach the admin UI at {bind} "
            f"({type(exc).__name__}: {exc}). Is the service running? "
            f"Check `nssm status <service>` or the launcher's AppStdout log.",
            file=err,
        )
        return 1
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        text = body.decode("utf-8", errors="replace")
    print(text, file=out)
    return 0


def _default_fetch_url(url: str, timeout: float) -> bytes:
    """stdlib urllib GET. Returns the raw response body bytes."""
    import urllib.request
    req = urllib.request.Request(url, method="GET")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return bytes(resp.read())


def _version_string() -> str:
    """Build the --version output string."""
    from recto import __version__
    return f"recto {__version__}"
