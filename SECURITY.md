# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| `2.0.x` | Yes |
| `1.0.x` | No |

## Reporting a vulnerability

Do not open a public GitHub issue for security vulnerabilities.

Report vulnerabilities privately through [GitHub Private Vulnerability Reporting](https://github.com/denissitnikov/seatstamp/security/advisories/new). Include minimal steps or a test case to reproduce, the affected files or version tag, and the security impact.

## Scope

Before reporting, check [`docs/threat-model.md`](docs/threat-model.md) for what this kit defends against and what is outside its threat model:

- In scope: Ed25519 signature or canonical framing bypasses in `LicenseTicket` or `UpdateManifest`, `SeatCoordinator` seat-cap or `revokedBefore` watermark bypasses, Stripe refund/dispute/livemode check bypasses, `UpdateChecker` host or path-prefix pinning bypasses, Worker CSRF or email-enumeration flaws, and unintended PII retention.
- Out of scope: local binary patching of a buyer's own `.app` bundle on macOS, or resetting a local trial by deleting all four local trial anchors plus the Keychain item (or running inside a fresh macOS VM).
