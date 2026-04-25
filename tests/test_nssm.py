"""Tests for recto.nssm.

The NssmClient wraps shell-outs to nssm.exe. All tests inject a stub
runner that records the cmd argv and returns a canned CompletedProcess,
so no real nssm.exe is invoked. AppEnvironmentExtra parsing is unit-
tested directly via split_environment_extra.
"""

from __future__ import annotations

import subprocess
from typing import Any

import pytest

from recto.nssm import (
    NSSM_FIELDS,
    NssmClient,
    NssmConfig,
    NssmError,
    NssmNotInstalledError,
    NssmServiceNotFoundError,
    NssmStatus,
    split_environment_extra,
)


# ---------------------------------------------------------------------------
# Stub runner
# ---------------------------------------------------------------------------


class FakeRunner:
    """subprocess.run stand-in.

    `responses` maps a tuple of cmd args (without nssm_exe) to a
    (returncode, stdout_bytes, stderr_bytes) tuple. Default response
    is (0, b'', b'') for any call not in the map. Records every call
    in `.calls` for assertions.
    """

    def __init__(
        self,
        responses: dict[tuple[str, ...], tuple[int, bytes, bytes]] | None = None,
    ) -> None:
        self.responses = responses if responses is not None else {}
        self.calls: list[list[str]] = []

    def __call__(
        self,
        args: list[str],
        *,
        capture_output: bool = True,
        timeout: float | None = 10.0,
        check: bool = False,
        **kwargs: Any,
    ) -> subprocess.CompletedProcess[bytes]:
        self.calls.append(list(args))
        # Strip the nssm_exe path; key on the rest.
        key = tuple(args[1:])
        rc, stdout, stderr = self.responses.get(key, (0, b"", b""))
        return subprocess.CompletedProcess(
            args=args, returncode=rc, stdout=stdout, stderr=stderr
        )


def _utf16(s: str) -> bytes:
    return s.encode("utf-16-le")


# ---------------------------------------------------------------------------
# split_environment_extra
# ---------------------------------------------------------------------------


class TestSplitEnvironmentExtra:
    def test_simple_pairs(self) -> None:
        out = split_environment_extra("FOO=bar\nBAZ=qux")
        assert out == [("FOO", "bar"), ("BAZ", "qux")]

    def test_blank_lines_skipped(self) -> None:
        out = split_environment_extra("FOO=bar\n\n\nBAZ=qux\n")
        assert out == [("FOO", "bar"), ("BAZ", "qux")]

    def test_value_with_equals_preserved(self) -> None:
        # Connection strings, base64 etc. routinely have '=' in the value.
        out = split_environment_extra("DB=Host=db;Pwd==xyz")
        assert out == [("DB", "Host=db;Pwd==xyz")]

    def test_line_without_equals_ignored(self) -> None:
        out = split_environment_extra("FOO=bar\nthis_is_garbage\nBAZ=qux")
        assert out == [("FOO", "bar"), ("BAZ", "qux")]

    def test_empty_key_ignored(self) -> None:
        out = split_environment_extra("=value\nGOOD=yes")
        assert out == [("GOOD", "yes")]

    def test_empty_input(self) -> None:
        assert split_environment_extra("") == []

    def test_value_can_be_empty(self) -> None:
        # Some services use empty-string env vars as flags.
        out = split_environment_extra("FLAG=\nVAL=present")
        assert out == [("FLAG", ""), ("VAL", "present")]


# ---------------------------------------------------------------------------
# NssmClient.status / get / set / reset
# ---------------------------------------------------------------------------


class TestNssmClientStatus:
    def test_status_running(self) -> None:
        runner = FakeRunner(
            responses={("status", "myservice"): (0, _utf16("SERVICE_RUNNING\r\n"), b"")}
        )
        client = NssmClient(nssm_exe="nssm.exe", runner=runner)
        assert client.status("myservice") == NssmStatus.SERVICE_RUNNING
        assert runner.calls[0] == ["nssm.exe", "status", "myservice"]

    def test_status_stopped(self) -> None:
        runner = FakeRunner(
            responses={("status", "x"): (0, _utf16("SERVICE_STOPPED"), b"")}
        )
        client = NssmClient(nssm_exe="nssm.exe", runner=runner)
        assert client.status("x") == NssmStatus.SERVICE_STOPPED

    def test_status_unknown_value_returned_verbatim(self) -> None:
        # A patched / future NSSM might emit a status we don't have a
        # constant for. Pass through so the caller can decide.
        runner = FakeRunner(
            responses={("status", "x"): (0, _utf16("SERVICE_NEW_THING"), b"")}
        )
        client = NssmClient(nssm_exe="nssm.exe", runner=runner)
        assert client.status("x") == "SERVICE_NEW_THING"


class TestNssmClientGet:
    def test_get_single_field(self) -> None:
        runner = FakeRunner(
            responses={
                ("get", "myservice", "AppPath"): (0, _utf16("C:\\python.exe"), b""),
            }
        )
        client = NssmClient(nssm_exe="nssm.exe", runner=runner)
        assert client.get("myservice", "AppPath") == "C:\\python.exe"

    def test_get_strips_trailing_whitespace(self) -> None:
        runner = FakeRunner(
            responses={
                ("get", "x", "AppPath"): (0, _utf16("C:\\python.exe\r\n"), b""),
            }
        )
        client = NssmClient(nssm_exe="nssm.exe", runner=runner)
        assert client.get("x", "AppPath") == "C:\\python.exe"

    def test_get_service_not_found_raises_specific_error(self) -> None:
        runner = FakeRunner(
            responses={
                ("get", "ghost", "AppPath"): (
                    1,
                    b"",
                    _utf16("Service does not exist"),
                ),
            }
        )
        client = NssmClient(nssm_exe="nssm.exe", runner=runner)
        with pytest.raises(NssmServiceNotFoundError):
            client.get("ghost", "AppPath")

    def test_get_other_error_raises_generic_nssm_error(self) -> None:
        runner = FakeRunner(
            responses={
                ("get", "x", "AppPath"): (
                    7,
                    b"",
                    _utf16("Some weird internal NSSM thing"),
                ),
            }
        )
        client = NssmClient(nssm_exe="nssm.exe", runner=runner)
        with pytest.raises(NssmError) as exc:
            client.get("x", "AppPath")
        # Should NOT be the specific subclass; it's a generic failure.
        assert not isinstance(exc.value, NssmServiceNotFoundError)


class TestNssmClientGetAll:
    def test_get_all_populates_all_canonical_fields(self) -> None:
        # Build responses for every canonical field. AppEnvironmentExtra
        # is the multi-line block of KEY=value entries.
        responses = {
            ("get", "svc", "AppPath"): (0, _utf16("C:\\python.exe"), b""),
            ("get", "svc", "AppParameters"): (0, _utf16("C:\\app\\main.py --foo"), b""),
            ("get", "svc", "AppDirectory"): (0, _utf16("C:\\app"), b""),
            ("get", "svc", "AppEnvironmentExtra"): (
                0,
                _utf16("API_KEY=secret123\nDB_URL=postgres://x"),
                b"",
            ),
            ("get", "svc", "AppExit"): (0, _utf16("Default Restart"), b""),
            ("get", "svc", "DisplayName"): (0, _utf16("My Service"), b""),
            ("get", "svc", "Description"): (0, _utf16("Does important things"), b""),
        }
        runner = FakeRunner(responses=responses)
        client = NssmClient(nssm_exe="nssm.exe", runner=runner)
        cfg = client.get_all("svc")
        assert isinstance(cfg, NssmConfig)
        assert cfg.service == "svc"
        assert cfg.app_path == "C:\\python.exe"
        assert cfg.app_parameters == "C:\\app\\main.py --foo"
        assert cfg.app_directory == "C:\\app"
        assert cfg.app_environment_extra == (
            "API_KEY=secret123",
            "DB_URL=postgres://x",
        )
        assert cfg.display_name == "My Service"
        # All canonical fields visited exactly once each.
        called_fields = [c[3] for c in runner.calls if len(c) >= 4 and c[1] == "get"]
        assert sorted(called_fields) == sorted(NSSM_FIELDS)

    def test_get_all_propagates_service_not_found(self) -> None:
        runner = FakeRunner(
            responses={
                ("get", "ghost", "AppPath"): (
                    1,
                    b"",
                    _utf16("Service does not exist"),
                ),
            }
        )
        client = NssmClient(nssm_exe="nssm.exe", runner=runner)
        with pytest.raises(NssmServiceNotFoundError):
            client.get_all("ghost")


class TestNssmClientSetReset:
    def test_set_writes_field(self) -> None:
        runner = FakeRunner()
        client = NssmClient(nssm_exe="nssm.exe", runner=runner)
        client.set("svc", "AppPath", "C:\\new.exe")
        assert runner.calls[-1] == ["nssm.exe", "set", "svc", "AppPath", "C:\\new.exe"]

    def test_set_failure_raises(self) -> None:
        runner = FakeRunner(
            responses={
                ("set", "svc", "Bad", "x"): (1, b"", _utf16("nope")),
            }
        )
        client = NssmClient(nssm_exe="nssm.exe", runner=runner)
        with pytest.raises(NssmError):
            client.set("svc", "Bad", "x")

    def test_reset_clears_field(self) -> None:
        runner = FakeRunner()
        client = NssmClient(nssm_exe="nssm.exe", runner=runner)
        client.reset("svc", "AppEnvironmentExtra")
        assert runner.calls[-1] == [
            "nssm.exe",
            "reset",
            "svc",
            "AppEnvironmentExtra",
        ]


class TestNssmExeResolution:
    def test_explicit_path_used_verbatim(self) -> None:
        runner = FakeRunner()
        client = NssmClient(nssm_exe="C:\\custom\\nssm.exe", runner=runner)
        # Don't actually call status; just read the property.
        assert client.nssm_exe == "C:\\custom\\nssm.exe"

    def test_missing_nssm_raises_specific_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            "recto.nssm.shutil.which", lambda _name: None
        )
        client = NssmClient(runner=FakeRunner())
        with pytest.raises(NssmNotInstalledError):
            _ = client.nssm_exe


# ---------------------------------------------------------------------------
# Decoder edge cases
# ---------------------------------------------------------------------------


class TestNssmDecoder:
    def test_utf8_fallback_when_not_utf16(self) -> None:
        # If NSSM emits UTF-8 (some patched builds), we should still
        # decode it. A plain-ascii string is valid both as UTF-8 and
        # UTF-16-LE-of-zeros, but odd-length forces UTF-8 path.
        runner = FakeRunner(
            responses={("status", "x"): (0, b"SERVICE_RUNNING", b"")}
        )
        client = NssmClient(nssm_exe="nssm.exe", runner=runner)
        # 'SERVICE_RUNNING' in UTF-16-LE would still succeed as a
        # decode; the test mainly ensures we don't raise.
        result = client.status("x")
        # The exact string depends on which decoder won; both branches
        # produce a string we can compare loosely.
        assert "SERVICE_RUNNING" in result or result.replace("\x00", "") == "SERVICE_RUNNING"
