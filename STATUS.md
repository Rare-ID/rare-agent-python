# Status

## Stability

Current repository status: usable for evaluation and early adoption, pre-`1.0`.

What is relatively stable:

- agent registration and attestation refresh flows
- hosted-signer and self-hosted key modes
- login material generation for Rare-compatible platforms

What may still change:

- CLI ergonomics
- recovery and upgrade workflow details
- helper APIs around state and local signer tooling

## Compatibility

| Component | Version | Depends on |
| --- | --- | --- |
| `rare-agent-sdk` | `0.2.0` | `rare-identity-protocol >= 0.1.0` |
| `rare-identity-protocol` | `0.1.0` | public protocol primitives |

Until `1.0`, breaking changes should be called out explicitly in release notes and README updates.
