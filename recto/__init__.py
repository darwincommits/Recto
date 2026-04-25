"""Recto — modern Windows-service wrapper.

Public API surface:
    recto.config.load_config        — parse + validate a service.yaml
    recto.config.ServiceConfig      — top-level dataclass
    recto.secrets.SecretSource      — ABC for pluggable secret backends
    recto.secrets.SecretMaterial    — sealed type returned by SecretSource.fetch
    recto.secrets.DirectSecret      — variant: secret materialized as a string
    recto.secrets.SigningCapability — variant: secret never leaves enclave
    recto.secrets.EnvSource         — passthrough backend reading os.environ
    recto.secrets.CredManSource     — Windows Credential Manager backend
    recto.secrets.register_source   — third-party backend registration
    recto.launcher.launch           — read config, fetch secrets, spawn child

Higher-level entry points (CLI, healthz probe loop, restart policy, comms
webhook dispatch) are wired in alongside the launcher in v0.1.
"""

__version__ = "0.1.0.dev0"
__all__ = ["__version__"]
