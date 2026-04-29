# Recto Phone App

MAUI Blazor scaffold for the Recto v0.4 phone-resident vault. The phone app
holds an Ed25519 keypair in the platform's hardware enclave (iOS Secure
Enclave / Android StrongBox) and biometric-gates every sign request a
Recto bootloader sends it.

See [`../docs/v0.4-protocol.md`](../docs/v0.4-protocol.md) for the
wire-protocol RFC. The app is under construction &mdash; today it builds,
launches on Windows, and shows a pairing empty-state shell. Network
pairing, enclave key generation, and the actual sign-request flow land
in follow-on sprints.

## Layout

- `Recto/Recto/` &mdash; MAUI host (Android, iOS, Mac Catalyst, Windows).
- `Recto/Recto.Shared/` &mdash; Razor components, layout, generic helpers
  (`Result<T>`, `Error`, `ICommandHandler`, `IQueryHandler`, decorator
  pipeline). All targeting `net10.0`.

## Build

Requires the .NET 10 SDK and the MAUI workload installed:

```sh
dotnet workload install maui
dotnet restore Recto.slnx
dotnet build Recto.slnx
```

For Windows desktop debugging, open `Recto.slnx` in Visual Studio, set
`Recto/Recto/Recto.csproj` as the startup project, target
`net10.0-windows10.0.19041.0`, and press F5.

## Status

This subtree is intentionally not committed yet. It will land in the
public Recto repo when v0.4 is shippable per the lineage's
public-domain / Apache-2.0 spirit.
