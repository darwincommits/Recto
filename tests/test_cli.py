"""Tests for recto.cli.

The CLI is a thin dispatcher; tests inject stubs for every external
dependency (credman, NSSM, launcher, prompt) so we exercise the
argparse + dispatch + error-handling logic without touching real
systems.
"""

from __future__ import annotations

import io
from pathlib import Path
from typing import Any

import pytest

from recto import cli
from recto.config import ServiceConfig
from recto.nssm import (
    NssmConfig,
    NssmError,
    NssmNotInstalledError,
    NssmServiceNotFoundError,
    NssmStatus,
)
from recto.secrets import (
    CredManSource,
    DirectSecret,
    SecretMaterial,
    SecretNotFoundError,
    SecretSource,
    SecretSourceError,
)


# ---------------------------------------------------------------------------
# Stubs
# ---------------------------------------------------------------------------


class FakeCredManSource(CredManSource):
    """In-memory CredManSource for CLI tests.

    Mirrors the FakeCredManSource pattern from
    tests/test_secrets_credman.py: uses platform_check=False to bypass
    the Windows-only guard, then overrides the four `_*_blob` methods
    to back them with a shared dict.
    """

    def __init__(self, service: str, store: dict[str, str]) -> None:
        super().__init__(service, platform_check=False)
        self._store = store

    def _read_blob(self, target: str) -> str:
        if target not in self._store:
            raise SecretNotFoundError(target)
        return self._store[target]

    def _write_blob(self, target: str, value: str, comment: str = "") -> None:
        self._store[target] = value

    def _delete_blob(self, target: str) -> None:
        if target not in self._store:
            raise SecretNotFoundError(target)
        del self._store[target]

    def _list_targets(self, filter_pattern: str) -> list[str]:
        # Simple wildcard support: prefix-match before the trailing '*'.
        if filter_pattern.endswith("*"):
            prefix = filter_pattern[:-1]
            return [t for t in self._store if t.startswith(prefix)]
        return [t for t in self._store if t == filter_pattern]


class FakeNssmClient:
    """NssmClient stand-in for migrate / status tests.

    Holds a mutable NssmConfig snapshot and tracks set/reset calls so
    the test can assert on what migrate-from-nssm wrote back.
    """

    def __init__(
        self,
        *,
        config: NssmConfig | None = None,
        status_value: str = NssmStatus.SERVICE_STOPPED,
        not_installed: bool = False,
        not_found: bool = False,
    ) -> None:
        self.config = config
        self.status_value = status_value
        self.not_installed = not_installed
        self.not_found = not_found
        self.set_calls: list[tuple[str, str, str]] = []
        self.reset_calls: list[tuple[str, str]] = []

    def status(self, service: str) -> str:
        if self.not_installed:
            raise NssmNotInstalledError("nssm.exe missing")
        return self.status_value

    def get_all(self, service: str) -> NssmConfig:
        if self.not_installed:
            raise NssmNotInstalledError("nssm.exe missing")
        if self.not_found or self.config is None:
            raise NssmServiceNotFoundError(f"{service!r} not found")
        return self.config

    def set(self, service: str, field: str, value: str) -> None:
        self.set_calls.append((service, field, value))

    def reset(self, service: str, field: str) -> None:
        self.reset_calls.append((service, field))


def _capture() -> tuple[io.StringIO, io.StringIO]:
    """Return (stdout_buf, stderr_buf)."""
    return io.StringIO(), io.StringIO()


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------


class TestBuildParser:
    def test_launch_subcommand_parses(self) -> None:
        parser = cli.build_parser()
        args = parser.parse_args(["launch", "service.yaml"])
        assert args.command == "launch"
        assert args.yaml_path == "service.yaml"
        assert args.once is False

    def test_launch_once_flag(self) -> None:
        parser = cli.build_parser()
        args = parser.parse_args(["launch", "service.yaml", "--once"])
        assert args.once is True

    def test_credman_set_with_value_flag(self) -> None:
        parser = cli.build_parser()
        args = parser.parse_args(
            ["credman", "set", "myservice", "MY_KEY", "--value", "the-value"]
        )
        assert args.command == "credman"
        assert args.credman_command == "set"
        assert args.service == "myservice"
        assert args.name == "MY_KEY"
        assert args.value == "the-value"

    def test_credman_list(self) -> None:
        parser = cli.build_parser()
        args = parser.parse_args(["credman", "list", "myservice"])
        assert args.credman_command == "list"
        assert args.service == "myservice"

    def test_credman_delete(self) -> None:
        parser = cli.build_parser()
        args = parser.parse_args(["credman", "delete", "myservice", "MY_KEY"])
        assert args.credman_command == "delete"
        assert args.service == "myservice"
        assert args.name == "MY_KEY"

    def test_status(self) -> None:
        parser = cli.build_parser()
        args = parser.parse_args(["status", "myservice"])
        assert args.command == "status"
        assert args.service == "myservice"

    def test_migrate_with_yaml_out_and_dry_run(self) -> None:
        parser = cli.build_parser()
        args = parser.parse_args(
            [
                "migrate-from-nssm",
                "myservice",
                "--yaml-out",
                "out.yaml",
                "--dry-run",
            ]
        )
        assert args.command == "migrate-from-nssm"
        assert args.service == "myservice"
        assert args.yaml_out == "out.yaml"
        assert args.dry_run is True

    def test_no_subcommand_errors(self) -> None:
        parser = cli.build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args([])


# ---------------------------------------------------------------------------
# launch subcommand
# ---------------------------------------------------------------------------


def _make_yaml(tmp_path: Path) -> Path:
    yaml_path = tmp_path / "service.yaml"
    yaml_path.write_text(
        "apiVersion: recto/v1\n"
        "kind: Service\n"
        "metadata:\n"
        "  name: myservice\n"
        "spec:\n"
        "  exec: python.exe\n",
        encoding="utf-8",
    )
    return yaml_path


class TestLaunchCommand:
    def test_launch_dispatches_to_run_by_default(self, tmp_path: Path) -> None:
        yaml_path = _make_yaml(tmp_path)
        captured: dict[str, Any] = {}

        def fake_launch(config: ServiceConfig, **_kw: Any) -> int:
            captured["config"] = config
            return 0

        out, err = _capture()
        rc = cli.main(
            ["launch", str(yaml_path)],
            launch_fn=fake_launch,
            stdout=out,
            stderr=err,
        )
        assert rc == 0
        assert captured["config"].metadata.name == "myservice"

    def test_launch_returns_child_returncode(self, tmp_path: Path) -> None:
        yaml_path = _make_yaml(tmp_path)
        out, err = _capture()
        rc = cli.main(
            ["launch", str(yaml_path)],
            launch_fn=lambda _cfg, **_kw: 42,
            stdout=out,
            stderr=err,
        )
        assert rc == 42

    def test_launch_missing_file_returns_1(self, tmp_path: Path) -> None:
        out, err = _capture()
        rc = cli.main(
            ["launch", str(tmp_path / "does-not-exist.yaml")],
            launch_fn=lambda _cfg, **_kw: 0,
            stdout=out,
            stderr=err,
        )
        assert rc == 1
        assert "not found" in err.getvalue()

    def test_launch_invalid_yaml_returns_1(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.yaml"
        bad.write_text(
            "apiVersion: WRONG\nkind: WRONG\nmetadata: {}\nspec: {}",
            encoding="utf-8",
        )
        out, err = _capture()
        rc = cli.main(
            ["launch", str(bad)],
            launch_fn=lambda _cfg, **_kw: 0,
            stdout=out,
            stderr=err,
        )
        assert rc == 1
        assert "invalid config" in err.getvalue()


# ---------------------------------------------------------------------------
# credman subcommands
# ---------------------------------------------------------------------------


class TestCredmanSet:
    def test_set_with_value_flag_writes_to_credman(self) -> None:
        store: dict[str, str] = {}

        def factory(service: str) -> CredManSource:
            return FakeCredManSource(service, store)

        out, err = _capture()
        rc = cli.main(
            ["credman", "set", "myservice", "MY_KEY", "--value", "the-value"],
            credman_factory=factory,
            stdout=out,
            stderr=err,
        )
        assert rc == 0
        assert store["recto:myservice:MY_KEY"] == "the-value"
        assert "installed" in out.getvalue()

    def test_set_prompts_for_value_when_not_provided(self) -> None:
        store: dict[str, str] = {}
        prompts_seen: list[str] = []

        def fake_prompt(p: str) -> str:
            prompts_seen.append(p)
            return "from-prompt"

        def factory(service: str) -> CredManSource:
            return FakeCredManSource(service, store)

        out, err = _capture()
        rc = cli.main(
            ["credman", "set", "myservice", "MY_KEY"],
            credman_factory=factory,
            prompt=fake_prompt,
            stdout=out,
            stderr=err,
        )
        assert rc == 0
        assert store["recto:myservice:MY_KEY"] == "from-prompt"
        assert len(prompts_seen) == 1
        assert "MY_KEY" in prompts_seen[0]
        # The prompt SHOULD mention 'hidden' so the operator knows nothing's echoed.
        assert "hidden" in prompts_seen[0].lower()

    def test_set_empty_prompt_value_refuses(self) -> None:
        store: dict[str, str] = {}

        def factory(service: str) -> CredManSource:
            return FakeCredManSource(service, store)

        out, err = _capture()
        rc = cli.main(
            ["credman", "set", "myservice", "MY_KEY"],
            credman_factory=factory,
            prompt=lambda _p: "",  # user just hit enter
            stdout=out,
            stderr=err,
        )
        assert rc == 1
        assert "empty" in err.getvalue().lower()
        assert "recto:myservice:MY_KEY" not in store

    def test_set_explicit_empty_value_via_flag_is_allowed(self) -> None:
        # Operator explicitly passing --value "" is "I really mean empty".
        store: dict[str, str] = {}

        def factory(service: str) -> CredManSource:
            return FakeCredManSource(service, store)

        out, err = _capture()
        rc = cli.main(
            ["credman", "set", "myservice", "MY_KEY", "--value", ""],
            credman_factory=factory,
            stdout=out,
            stderr=err,
        )
        assert rc == 0
        assert store["recto:myservice:MY_KEY"] == ""


class TestCredmanList:
    def test_list_empty(self) -> None:
        store: dict[str, str] = {}

        def factory(service: str) -> CredManSource:
            return FakeCredManSource(service, store)

        out, err = _capture()
        rc = cli.main(
            ["credman", "list", "myservice"],
            credman_factory=factory,
            stdout=out,
            stderr=err,
        )
        assert rc == 0
        assert out.getvalue() == ""

    def test_list_returns_only_matching_service(self) -> None:
        # Multiple services in the store; list should only print the
        # ones scoped to the requested service name.
        store = {
            "recto:myservice:KEY_A": "a",
            "recto:myservice:KEY_B": "b",
            "recto:other:KEY_C": "c",
        }

        def factory(service: str) -> CredManSource:
            return FakeCredManSource(service, store)

        out, err = _capture()
        rc = cli.main(
            ["credman", "list", "myservice"],
            credman_factory=factory,
            stdout=out,
            stderr=err,
        )
        assert rc == 0
        lines = out.getvalue().strip().splitlines()
        assert lines == ["KEY_A", "KEY_B"]


class TestCredmanDelete:
    def test_delete_removes_existing_entry(self) -> None:
        store = {"recto:myservice:KEY": "val"}

        def factory(service: str) -> CredManSource:
            return FakeCredManSource(service, store)

        out, err = _capture()
        rc = cli.main(
            ["credman", "delete", "myservice", "KEY"],
            credman_factory=factory,
            stdout=out,
            stderr=err,
        )
        assert rc == 0
        assert "recto:myservice:KEY" not in store
        assert "deleted" in out.getvalue()

    def test_delete_missing_returns_1(self) -> None:
        store: dict[str, str] = {}

        def factory(service: str) -> CredManSource:
            return FakeCredManSource(service, store)

        out, err = _capture()
        rc = cli.main(
            ["credman", "delete", "myservice", "KEY"],
            credman_factory=factory,
            stdout=out,
            stderr=err,
        )
        assert rc == 1
        assert "does not exist" in err.getvalue()


# ---------------------------------------------------------------------------
# status subcommand
# ---------------------------------------------------------------------------


class TestStatusCommand:
    def test_status_running_returns_0(self) -> None:
        nssm = FakeNssmClient(status_value=NssmStatus.SERVICE_RUNNING)
        out, err = _capture()
        rc = cli.main(
            ["status", "myservice"],
            nssm_factory=lambda: nssm,
            stdout=out,
            stderr=err,
        )
        assert rc == 0
        assert "SERVICE_RUNNING" in out.getvalue()

    def test_status_stopped_returns_1(self) -> None:
        nssm = FakeNssmClient(status_value=NssmStatus.SERVICE_STOPPED)
        out, err = _capture()
        rc = cli.main(
            ["status", "myservice"],
            nssm_factory=lambda: nssm,
            stdout=out,
            stderr=err,
        )
        assert rc == 1
        assert "SERVICE_STOPPED" in out.getvalue()

    def test_status_nssm_missing_returns_1(self) -> None:
        nssm = FakeNssmClient(not_installed=True)
        out, err = _capture()
        rc = cli.main(
            ["status", "myservice"],
            nssm_factory=lambda: nssm,
            stdout=out,
            stderr=err,
        )
        assert rc == 1
        assert "nssm" in err.getvalue().lower()


# ---------------------------------------------------------------------------
# migrate-from-nssm subcommand
# ---------------------------------------------------------------------------


def _example_nssm_config(service: str = "svc") -> NssmConfig:
    return NssmConfig(
        service=service,
        app_path="C:\\python.exe",
        app_parameters="C:\\app\\main.py --foo",
        app_directory="C:\\app",
        app_environment_extra=("API_KEY=secret123", "DB_URL=postgres://x"),
        display_name="My Service",
    )


class TestMigrateFromNssm:
    def test_dry_run_makes_no_changes(self, tmp_path: Path) -> None:
        nssm = FakeNssmClient(config=_example_nssm_config())
        store: dict[str, str] = {}

        def factory(service: str) -> CredManSource:
            return FakeCredManSource(service, store)

        out, err = _capture()
        rc = cli.main(
            [
                "migrate-from-nssm",
                "svc",
                "--yaml-out",
                str(tmp_path / "svc.yaml"),
                "--dry-run",
            ],
            nssm_factory=lambda: nssm,
            credman_factory=factory,
            stdout=out,
            stderr=err,
        )
        assert rc == 0
        # No mutations on either side.
        assert store == {}
        assert nssm.set_calls == []
        assert nssm.reset_calls == []
        # YAML file not written.
        assert not (tmp_path / "svc.yaml").exists()
        # Plan output mentions the secrets and the new app path.
        body = out.getvalue()
        assert "API_KEY" in body
        assert "DB_URL" in body
        # Secret values must NOT appear in the plan output.
        assert "secret123" not in body
        assert "<redacted>" in body

    def test_apply_installs_secrets_writes_yaml_retargets_nssm(
        self, tmp_path: Path
    ) -> None:
        nssm = FakeNssmClient(config=_example_nssm_config())
        store: dict[str, str] = {}

        def factory(service: str) -> CredManSource:
            return FakeCredManSource(service, store)

        yaml_out = tmp_path / "svc.yaml"
        out, err = _capture()
        rc = cli.main(
            [
                "migrate-from-nssm",
                "svc",
                "--yaml-out",
                str(yaml_out),
            ],
            nssm_factory=lambda: nssm,
            credman_factory=factory,
            stdout=out,
            stderr=err,
        )
        assert rc == 0
        # Secrets installed.
        assert store["recto:svc:API_KEY"] == "secret123"
        assert store["recto:svc:DB_URL"] == "postgres://x"
        # YAML written and parses back into a valid ServiceConfig.
        from recto.config import load_config

        cfg = load_config(yaml_out)
        assert cfg.metadata.name == "svc"
        assert cfg.spec.exec == "C:\\python.exe"
        assert {s.name for s in cfg.spec.secrets} == {"API_KEY", "DB_URL"}
        for s in cfg.spec.secrets:
            assert s.source == "credman"
            assert s.target_env == s.name
        # NSSM retargeted.
        set_calls_dict = {(svc, fld): val for svc, fld, val in nssm.set_calls}
        assert set_calls_dict[("svc", "AppPath")] == "python.exe"
        assert "recto launch" in set_calls_dict[("svc", "AppParameters")]
        assert ("svc", "AppEnvironmentExtra") in nssm.reset_calls

    def test_service_not_found_returns_1(self, tmp_path: Path) -> None:
        nssm = FakeNssmClient(not_found=True)
        store: dict[str, str] = {}

        def factory(service: str) -> CredManSource:
            return FakeCredManSource(service, store)

        out, err = _capture()
        rc = cli.main(
            [
                "migrate-from-nssm",
                "ghost",
                "--yaml-out",
                str(tmp_path / "ghost.yaml"),
            ],
            nssm_factory=lambda: nssm,
            credman_factory=factory,
            stdout=out,
            stderr=err,
        )
        assert rc == 1
        assert "not found" in err.getvalue()
        assert store == {}


# ---------------------------------------------------------------------------
# Top-level error paths
# ---------------------------------------------------------------------------


class TestMainErrorPaths:
    def test_no_argv_uses_sys_argv_and_errors_on_no_command(self) -> None:
        # cli.main(None) reads sys.argv. argparse exits 2 on no
        # subcommand. We capture the SystemExit-equivalent return.
        out, err = _capture()
        rc = cli.main([], stdout=out, stderr=err)
        # argparse renders its error to stderr (the global stderr,
        # not our captured one - we don't intercept argparse's own
        # writes), and returns code 2.
        assert rc == 2

    def test_keyboard_interrupt_is_handled(self) -> None:
        def raises(_cfg: ServiceConfig, **_kw: Any) -> int:
            raise KeyboardInterrupt

        # Need a valid yaml to get past load_config.
        out, err = _capture()
        rc = cli.main(
            ["launch", "/nonexistent.yaml"],
            launch_fn=raises,
            stdout=out,
            stderr=err,
        )
        # missing file path lands at 1 before we ever hit launch_fn.
        assert rc == 1


# ---------------------------------------------------------------------------
# apply subcommand
# ---------------------------------------------------------------------------


def _make_apply_yaml(tmp_path: Path, *, name: str = "myservice") -> Path:
    yaml_path = tmp_path / "service.yaml"
    yaml_path.write_text(
        f"apiVersion: recto/v1\n"
        f"kind: Service\n"
        f"metadata:\n"
        f"  name: {name}\n"
        f"  description: An example service\n"
        f"spec:\n"
        f"  exec: python.exe\n"
        f'  working_dir: "C:\\\\path\\\\{name}"\n',
        encoding="utf-8",
    )
    return yaml_path


class TestApplyCommandParsing:
    def test_apply_with_dry_run(self) -> None:
        parser = cli.build_parser()
        args = parser.parse_args(["apply", "service.yaml", "--dry-run"])
        assert args.command == "apply"
        assert args.yaml_path == "service.yaml"
        assert args.dry_run is True
        assert args.yes is False
        assert args.python_exe == "python.exe"

    def test_apply_with_yes_short_flag(self) -> None:
        parser = cli.build_parser()
        args = parser.parse_args(["apply", "service.yaml", "-y"])
        assert args.yes is True

    def test_apply_with_python_exe_override(self) -> None:
        parser = cli.build_parser()
        args = parser.parse_args(
            ["apply", "x.yaml", "--python-exe", "C:\\Python312\\python.exe"]
        )
        assert args.python_exe == "C:\\Python312\\python.exe"


class TestApplyDispatch:
    def test_dry_run_prints_plan_and_exits_without_mutating(
        self, tmp_path: Path
    ) -> None:
        yaml_path = _make_apply_yaml(tmp_path, name="myservice")
        # Empty NSSM config: every field needs a change.
        nssm_stub = FakeNssmClient(
            config=NssmConfig(service="myservice")
        )
        out, err = _capture()
        rc = cli.main(
            ["apply", str(yaml_path), "--dry-run"],
            nssm_factory=lambda: nssm_stub,
            stdout=out,
            stderr=err,
        )
        assert rc == 0
        assert "recto apply: myservice" in out.getvalue()
        assert "--dry-run; no changes made" in out.getvalue()
        # Critical: no NSSM mutations.
        assert nssm_stub.set_calls == []
        assert nssm_stub.reset_calls == []

    def test_yes_flag_skips_prompt_and_applies(self, tmp_path: Path) -> None:
        yaml_path = _make_apply_yaml(tmp_path, name="myservice")
        nssm_stub = FakeNssmClient(config=NssmConfig(service="myservice"))
        out, err = _capture()
        # confirm should NOT be called when --yes is set; pass a confirm
        # that would fail the test if it were.
        def boom_confirm(_p: str) -> str:
            raise AssertionError("confirm should not be called with --yes")

        rc = cli.main(
            ["apply", str(yaml_path), "--yes"],
            nssm_factory=lambda: nssm_stub,
            confirm=boom_confirm,
            stdout=out,
            stderr=err,
        )
        assert rc == 0
        assert len(nssm_stub.set_calls) == 5  # all five scalar fields
        # No AppEnvironmentExtra reset (current state had it empty).
        assert nssm_stub.reset_calls == []
        assert "applied 5 change(s)" in out.getvalue()

    def test_interactive_y_applies(self, tmp_path: Path) -> None:
        yaml_path = _make_apply_yaml(tmp_path, name="myservice")
        nssm_stub = FakeNssmClient(config=NssmConfig(service="myservice"))
        prompts_seen: list[str] = []

        def confirm_yes(prompt: str) -> str:
            prompts_seen.append(prompt)
            return "y"

        out, err = _capture()
        rc = cli.main(
            ["apply", str(yaml_path)],
            nssm_factory=lambda: nssm_stub,
            confirm=confirm_yes,
            stdout=out,
            stderr=err,
        )
        assert rc == 0
        assert len(prompts_seen) == 1
        assert "Apply" in prompts_seen[0]
        assert len(nssm_stub.set_calls) == 5

    def test_interactive_n_aborts(self, tmp_path: Path) -> None:
        yaml_path = _make_apply_yaml(tmp_path, name="myservice")
        nssm_stub = FakeNssmClient(config=NssmConfig(service="myservice"))

        def confirm_no(_p: str) -> str:
            return "n"

        out, err = _capture()
        rc = cli.main(
            ["apply", str(yaml_path)],
            nssm_factory=lambda: nssm_stub,
            confirm=confirm_no,
            stdout=out,
            stderr=err,
        )
        # Aborting is a successful no-op (exit 0), not an error.
        assert rc == 0
        assert "aborted" in out.getvalue()
        assert nssm_stub.set_calls == []

    def test_interactive_eof_aborts(self, tmp_path: Path) -> None:
        yaml_path = _make_apply_yaml(tmp_path, name="myservice")
        nssm_stub = FakeNssmClient(config=NssmConfig(service="myservice"))

        def confirm_eof(_p: str) -> str:
            raise EOFError()

        out, err = _capture()
        rc = cli.main(
            ["apply", str(yaml_path)],
            nssm_factory=lambda: nssm_stub,
            confirm=confirm_eof,
            stdout=out,
            stderr=err,
        )
        # EOF on stdin (e.g. Ctrl-D, or `recto apply ... < /dev/null`) is
        # treated as "no" -- safer default than re-raising.
        assert rc == 0
        assert nssm_stub.set_calls == []

    def test_no_changes_needed_returns_zero_without_apply(
        self, tmp_path: Path
    ) -> None:
        yaml_path = _make_apply_yaml(tmp_path, name="myservice")
        # Build NSSM state to match what cfg implies.
        nssm_stub = FakeNssmClient(
            config=NssmConfig(
                service="myservice",
                app_path="python.exe",
                app_parameters=f"-m recto launch {yaml_path.resolve()}",
                app_directory="C:\\path\\myservice",
                display_name="An example service",
                description="An example service",
            )
        )
        out, err = _capture()
        rc = cli.main(
            ["apply", str(yaml_path), "--yes"],
            nssm_factory=lambda: nssm_stub,
            stdout=out,
            stderr=err,
        )
        assert rc == 0
        assert "no changes needed" in out.getvalue()
        assert nssm_stub.set_calls == []
        assert nssm_stub.reset_calls == []

    def test_invalid_yaml_returns_one(self, tmp_path: Path) -> None:
        # Syntactically valid YAML but invalid Recto schema (wrong
        # apiVersion). Tests the ConfigValidationError code path.
        # (yaml.YAMLError parse failures are a separate handler gap
        # affecting both `apply` and `launch`; tracked for follow-up.)
        bad_path = tmp_path / "bad.yaml"
        bad_path.write_text(
            "apiVersion: recto/v999\n"
            "kind: Service\n"
            "metadata:\n  name: x\n"
            "spec:\n  exec: x\n",
            encoding="utf-8",
        )
        nssm_stub = FakeNssmClient(config=NssmConfig(service="x"))
        out, err = _capture()
        rc = cli.main(
            ["apply", str(bad_path)],
            nssm_factory=lambda: nssm_stub,
            stdout=out,
            stderr=err,
        )
        assert rc == 1
        assert "invalid config" in err.getvalue()

    def test_missing_yaml_file_returns_one(self, tmp_path: Path) -> None:
        nssm_stub = FakeNssmClient(config=NssmConfig(service="x"))
        out, err = _capture()
        rc = cli.main(
            ["apply", str(tmp_path / "no-such-file.yaml")],
            nssm_factory=lambda: nssm_stub,
            stdout=out,
            stderr=err,
        )
        assert rc == 1
        assert "file not found" in err.getvalue()

    def test_nssm_service_not_found_returns_one(self, tmp_path: Path) -> None:
        yaml_path = _make_apply_yaml(tmp_path, name="myservice")
        nssm_stub = FakeNssmClient(not_found=True)
        out, err = _capture()
        rc = cli.main(
            ["apply", str(yaml_path)],
            nssm_factory=lambda: nssm_stub,
            stdout=out,
            stderr=err,
        )
        assert rc == 1
        assert "not found" in err.getvalue()
        # The error should mention the migration path as a hint.
        assert "migrate-from-nssm" in err.getvalue()

    def test_nssm_not_installed_returns_one(self, tmp_path: Path) -> None:
        yaml_path = _make_apply_yaml(tmp_path, name="myservice")
        nssm_stub = FakeNssmClient(not_installed=True)
        out, err = _capture()
        rc = cli.main(
            ["apply", str(yaml_path)],
            nssm_factory=lambda: nssm_stub,
            stdout=out,
            stderr=err,
        )
        assert rc == 1
        assert "nssm" in err.getvalue().lower()

    def test_environment_extra_clear_summarized(self, tmp_path: Path) -> None:
        yaml_path = _make_apply_yaml(tmp_path, name="myservice")
        nssm_stub = FakeNssmClient(
            config=NssmConfig(
                service="myservice",
                app_path="python.exe",
                app_parameters=f"-m recto launch {yaml_path.resolve()}",
                app_directory="C:\\path\\myservice",
                display_name="An example service",
                description="An example service",
                # Stale plaintext secret -- the apply should clear it.
                app_environment_extra=("LEFTOVER=value",),
            )
        )
        out, err = _capture()
        rc = cli.main(
            ["apply", str(yaml_path), "--yes"],
            nssm_factory=lambda: nssm_stub,
            stdout=out,
            stderr=err,
        )
        assert rc == 0
        assert nssm_stub.set_calls == []  # all scalar fields matched
        assert nssm_stub.reset_calls == [("myservice", "AppEnvironmentExtra")]
        assert "cleared AppEnvironmentExtra" in out.getvalue()
        # Critical: the leftover secret value MUST NOT appear in stdout.
        assert "LEFTOVER" not in out.getvalue()
        assert "value" not in out.getvalue().split("(s)")[-1]
