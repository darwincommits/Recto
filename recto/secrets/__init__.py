"""Secret-source plugin layer.

Each concrete backend (Credential Manager, Keychain, AWS Secrets Manager,
Vault, hardware enclave, etc.) implements the SecretSource ABC and returns
a SecretMaterial value. The launcher consumes SecretMaterial and arranges
for the supervised process to access the secret — either via env var
(DirectSecret) or via a local-socket sign-helper (SigningCapability,
v0.4+ hardware-enclave backends).

The boundary between "what the backend produces" and "how the launcher
consumes it" is the load-bearing seam in Recto's design. Adding a new
backend MUST NOT require changes to recto.launcher or to any consumer's
service.yaml beyond the source: selector.

Registry
--------

Backends are registered under the short `source:` selector that appears
in `service.yaml` (e.g. `source: credman`). Built-ins register on import
of this module. Third-party backends (or v0.3 cross-platform additions)
register at import time via `register_source(name, factory)`. The launcher
calls `resolve_source(name, service_name)` to materialize an instance.

Each registered factory takes one argument — the service name from
`metadata.name` — so backends that scope per-service (CredManSource,
hardware-enclave) can be constructed correctly. Backends that don't care
about the service name simply ignore it.
"""

from __future__ import annotations

from collections.abc import Callable

from recto.secrets.base import (
    DirectSecret,
    SecretMaterial,
    SecretNotFoundError,
    SecretSource,
    SecretSourceError,
    SigningCapability,
)
from recto.secrets.credman import CredManSource
from recto.secrets.dpapi_machine import DpapiMachineSource
from recto.secrets.env import EnvSource


class UnknownSecretSourceError(SecretSourceError):
    """A `spec.secrets[].source` value has no registered backend.

    Raised by `resolve_source` at launch-time, before any child spawn,
    so a typo'd source name surfaces as a clean config error rather than
    a missing-secret crash mid-flight.
    """


SourceFactory = Callable[[str], SecretSource]
"""Callable that takes a service name and returns a configured SecretSource."""


_SOURCE_FACTORIES: dict[str, SourceFactory] = {}


def register_source(name: str, factory: SourceFactory) -> None:
    """Register a SecretSource factory under the given selector name.

    The factory is called with the service name (`metadata.name` from the
    service.yaml) and must return a configured SecretSource. It is called
    once per launch, before any secret fetch.

    Re-registering the same name overwrites the previous factory; this is
    intentional so test fixtures can swap a real backend for an in-memory
    stub.
    """
    if not name:
        raise SecretSourceError("secret source name must be non-empty")
    _SOURCE_FACTORIES[name] = factory


def resolve_source(name: str, service: str) -> SecretSource:
    """Look up and instantiate a registered SecretSource.

    Raises:
        UnknownSecretSourceError: no backend registered under `name`.
            Error message lists the registered selectors so a typo is
            obvious without grepping the codebase.
    """
    factory = _SOURCE_FACTORIES.get(name)
    if factory is None:
        registered = sorted(_SOURCE_FACTORIES.keys())
        raise UnknownSecretSourceError(
            f"unknown secret source {name!r}; "
            f"registered backends: {registered}"
        )
    return factory(service)


def registered_sources() -> list[str]:
    """Sorted list of registered backend selector names. Used by the CLI's
    `recto sources list` and by error messages."""
    return sorted(_SOURCE_FACTORIES.keys())


# Built-in backends register on import. EnvSource ignores the service-name
# argument; CredManSource scopes to it via the 'recto:{service}:{secret}'
# target convention. Adding a new built-in backend means: define the
# class, then add a register_source(...) call here.
register_source("env", lambda _service: EnvSource())
register_source("credman", lambda service: CredManSource(service))
register_source(
    "dpapi-machine",
    lambda service: DpapiMachineSource(service),
)


__all__ = [
    "CredManSource",
    "DirectSecret",
    "DpapiMachineSource",
    "EnvSource",
    "SecretMaterial",
    "SecretNotFoundError",
    "SecretSource",
    "SecretSourceError",
    "SigningCapability",
    "SourceFactory",
    "UnknownSecretSourceError",
    "register_source",
    "registered_sources",
    "resolve_source",
]
