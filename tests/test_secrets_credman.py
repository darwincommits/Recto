"""Tests for the Windows Credential Manager backend.

Most tests subclass CredManSource and override the four `_*_blob` /
`_list_targets` methods to back them with an in-memory dict. This lets
us cover the high-level CredManSource logic on any platform; the actual
ctypes->advapi32 plumbing is verified at first-deploy on a real Windows
host (and in v0.2 via a Windows GitHub Actions runner).
"""

from __future__ import annotations

import sys

import pytest

from recto.secrets.base import (
    DirectSecret,
    SecretNotFoundError,
    SecretSourceError,
)
from recto.secrets.credman import (
    CredManSource,
    format_target,
    parse_target,
)

# ---------------------------------------------------------------------------
# In-memory CredManSource subclass used by every test below
# ---------------------------------------------------------------------------


class _FakeStore:
    """Stand-in for the host's Credential Manager storage."""

    def __init__(self) -> None:
        self.data: dict[str, str] = {}

    def read(self, target: str) -> str:
        if target not in self.data:
            raise SecretNotFoundError(f"credential {target!r} not found")
        return self.data[target]

    def write(self, target: str, value: str, comment: str = "") -> None:
        self.data[target] = value

    def delete(self, target: str) -> None:
        if target not in self.data:
            raise SecretNotFoundError(f"credential {target!r} not found")
        del self.data[target]

    def list(self, pattern: str) -> list[str]:
        # Pattern is 'recto:<service>:*' — strip trailing '*' and prefix-match.
        if pattern.endswith("*"):
            prefix = pattern[:-1]
            return [k for k in self.data if k.startswith(prefix)]
        return [k for k in self.data if k == pattern]


class FakeCredManSource(CredManSource):
    """CredManSource backed by an in-memory dict for testability on Linux."""

    def __init__(self, service: str, store: _FakeStore | None = None):
        super().__init__(service, platform_check=False)
        self._store = store if store is not None else _FakeStore()

    def _read_blob(self, target: str) -> str:
        return self._store.read(target)

    def _write_blob(self, target: str, value: str, comment: str = "") -> None:
        self._store.write(target, value, comment)

    def _delete_blob(self, target: str) -> None:
        self._store.delete(target)

    def _list_targets(self, filter_pattern: str) -> list[str]:
        return self._store.list(filter_pattern)


# ---------------------------------------------------------------------------
# Target-name formatting helpers
# ---------------------------------------------------------------------------


class TestFormatTarget:
    def test_basic(self) -> None:
        assert format_target("myservice", "MY_API_KEY") == "recto:myservice:MY_API_KEY"

    def test_rejects_colon_in_service(self) -> None:
        with pytest.raises(SecretSourceError):
            format_target("ver:so", "K")

    def test_rejects_colon_in_secret(self) -> None:
        with pytest.raises(SecretSourceError):
            format_target("myservice", "K:1")

    def test_rejects_empty_service(self) -> None:
        with pytest.raises(SecretSourceError):
            format_target("", "K")

    def test_rejects_empty_secret(self) -> None:
        with pytest.raises(SecretSourceError):
            format_target("myservice", "")


class TestParseTarget:
    def test_round_trip(self) -> None:
        t = format_target("myservice", "MY_API_KEY")
        parsed = parse_target(t)
        assert parsed == ("myservice", "MY_API_KEY")

    def test_non_recto_returns_none(self) -> None:
        # Other apps' Cred Manager entries shouldn't be parsed as ours.
        assert parse_target("Microsoft_OC1:bar") is None
        assert parse_target("git:https://github.com") is None

    def test_malformed_recto_target_returns_none(self) -> None:
        # Has the prefix but no ':' separator after it.
        assert parse_target("recto:no_secret_separator") is None
        # Has the prefix and separator but empty parts.
        assert parse_target("recto::secret") is None
        assert parse_target("recto:service:") is None


# ---------------------------------------------------------------------------
# CredManSource constructor + platform check
# ---------------------------------------------------------------------------


class TestConstructor:
    @pytest.mark.skipif(sys.platform == "win32", reason="Linux/macOS only")
    def test_raises_on_non_windows_by_default(self) -> None:
        with pytest.raises(NotImplementedError):
            CredManSource("myservice")

    def test_test_mode_works_on_any_platform(self) -> None:
        src = CredManSource("myservice", platform_check=False)
        assert src.name == "credman"
        assert src.service == "myservice"

    def test_rejects_empty_service(self) -> None:
        with pytest.raises(SecretSourceError):
            CredManSource("", platform_check=False)

    def test_rejects_colon_in_service(self) -> None:
        with pytest.raises(SecretSourceError):
            CredManSource("ver:so", platform_check=False)


# ---------------------------------------------------------------------------
# fetch() behavior
# ---------------------------------------------------------------------------


class TestFetch:
    def test_fetch_returns_direct_secret(self) -> None:
        store = _FakeStore()
        store.write("recto:myservice:MY_API_KEY", "secret-value")
        src = FakeCredManSource("myservice", store)
        result = src.fetch("MY_API_KEY", {})
        assert isinstance(result, DirectSecret)
        assert result.value == "secret-value"

    def test_fetch_missing_required_raises(self) -> None:
        src = FakeCredManSource("myservice")
        with pytest.raises(SecretNotFoundError):
            src.fetch("MISSING", {})

    def test_fetch_missing_optional_returns_empty(self) -> None:
        src = FakeCredManSource("myservice")
        result = src.fetch("MISSING", {"required": False})
        assert isinstance(result, DirectSecret)
        assert result.value == ""

    def test_fetch_does_not_log_value(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        store = _FakeStore()
        store.write("recto:myservice:K", "very-secret-value")
        src = FakeCredManSource("myservice", store)
        src.fetch("K", {})
        captured = capsys.readouterr()
        assert "very-secret-value" not in captured.out
        assert "very-secret-value" not in captured.err


# ---------------------------------------------------------------------------
# write() / delete() / rotate()
# ---------------------------------------------------------------------------


class TestWrite:
    def test_write_stores_value(self) -> None:
        store = _FakeStore()
        src = FakeCredManSource("myservice", store)
        src.write("MY_API_KEY", "v1")
        assert store.data["recto:myservice:MY_API_KEY"] == "v1"

    def test_write_upserts_existing(self) -> None:
        store = _FakeStore()
        store.write("recto:myservice:MY_API_KEY", "old")
        src = FakeCredManSource("myservice", store)
        src.write("MY_API_KEY", "new")
        assert store.data["recto:myservice:MY_API_KEY"] == "new"

    def test_write_then_fetch_round_trip(self) -> None:
        src = FakeCredManSource("myservice")
        src.write("MY_API_KEY", "abc123")
        result = src.fetch("MY_API_KEY", {})
        assert isinstance(result, DirectSecret)
        assert result.value == "abc123"


class TestDelete:
    def test_delete_removes(self) -> None:
        store = _FakeStore()
        store.write("recto:myservice:MY_API_KEY", "v")
        src = FakeCredManSource("myservice", store)
        src.delete("MY_API_KEY")
        assert "recto:myservice:MY_API_KEY" not in store.data

    def test_delete_missing_raises(self) -> None:
        src = FakeCredManSource("myservice")
        with pytest.raises(SecretNotFoundError):
            src.delete("MISSING")


class TestRotate:
    def test_supports_rotation(self) -> None:
        assert FakeCredManSource("myservice").supports_rotation() is True

    def test_rotate_replaces_value(self) -> None:
        src = FakeCredManSource("myservice")
        src.write("MY_API_KEY", "v1")
        src.rotate("MY_API_KEY", "v2")
        assert src.fetch("MY_API_KEY", {}).value == "v2"  # type: ignore[union-attr]


# ---------------------------------------------------------------------------
# list_names() — service-scoped enumeration
# ---------------------------------------------------------------------------


class TestListNames:
    def test_empty_store(self) -> None:
        assert FakeCredManSource("myservice").list_names() == []

    def test_lists_only_this_service(self) -> None:
        store = _FakeStore()
        # Three different services in the same store.
        store.write("recto:myservice:MY_API_KEY", "v")
        store.write("recto:myservice:WEBHOOK_TOKEN", "v")
        store.write("recto:allthruit:ANTHROPIC_KEY", "v")
        store.write("recto:other:UNRELATED", "v")
        # Plus a non-Recto entry to make sure we filter.
        store.write("Microsoft_OC1:foo", "v")

        svc = FakeCredManSource("myservice", store)
        assert svc.list_names() == ["MY_API_KEY", "WEBHOOK_TOKEN"]

        allthruit = FakeCredManSource("allthruit", store)
        assert allthruit.list_names() == ["ANTHROPIC_KEY"]

        unknown = FakeCredManSource("nonexistent", store)
        assert unknown.list_names() == []

    def test_returns_sorted(self) -> None:
        store = _FakeStore()
        # Insert in random order; list_names should sort.
        for name in ["ZED", "alpha", "MID"]:
            store.write(f"recto:myservice:{name}", "v")
        names = FakeCredManSource("myservice", store).list_names()
        assert names == sorted(names)


# ---------------------------------------------------------------------------
# Integration smoke test
# ---------------------------------------------------------------------------


class TestEndToEnd:
    def test_full_lifecycle(self) -> None:
        """Mirrors a canonical secret-install flow:
        write -> list -> fetch -> rotate -> delete."""
        src = FakeCredManSource("myservice")

        # No secrets installed yet.
        assert src.list_names() == []

        # Install MY_API_KEY + WEBHOOK_TOKEN.
        src.write("MY_API_KEY", "key-v1", comment="example API bearer")
        src.write("WEBHOOK_TOKEN", "push-token-v1")

        # List shows both.
        assert src.list_names() == ["MY_API_KEY", "WEBHOOK_TOKEN"]

        # Fetch returns DirectSecret with current values.
        a = src.fetch("MY_API_KEY", {})
        b = src.fetch("WEBHOOK_TOKEN", {})
        assert isinstance(a, DirectSecret)
        assert isinstance(b, DirectSecret)
        assert a.value == "key-v1"
        assert b.value == "push-token-v1"

        # Rotate MY_API_KEY.
        src.rotate("MY_API_KEY", "key-v2")
        assert src.fetch("MY_API_KEY", {}).value == "key-v2"  # type: ignore[union-attr]

        # Delete WEBHOOK_TOKEN.
        src.delete("WEBHOOK_TOKEN")
        assert src.list_names() == ["MY_API_KEY"]
        with pytest.raises(SecretNotFoundError):
            src.fetch("WEBHOOK_TOKEN", {})
