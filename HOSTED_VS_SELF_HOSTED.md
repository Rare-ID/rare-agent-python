# Hosted vs Self-Hosted

Rare agent flows support two key-management models.

## Hosted Signer

Rare manages signing on behalf of the agent.

Use this mode when:

- you want the fastest adoption path
- you do not want to manage Ed25519 private keys directly
- you are comfortable relying on Rare for hosted signing behavior

Tradeoffs:

- simpler integration
- less local key-management burden
- more trust placed in Rare operational services

## Self-Hosted

The agent keeps its own Ed25519 private key and signs locally.

Use this mode when:

- you want stronger local control of signing keys
- you need tighter operational separation from Rare hosted services
- your security model prefers local or customer-controlled key custody

Tradeoffs:

- more operational responsibility
- you must protect local key files and signer IPC
- recovery and rotation workflows become your responsibility

## Local Signer Daemon

`rare-signer` is the recommended self-hosted pattern when you want the SDK process to avoid loading the private key directly.

## Trust Boundary Summary

- Hosted signer: trust Rare for signing operations
- Self-hosted: trust your own environment for key custody
- In both modes, platforms should still verify the resulting attestation and delegation artifacts locally
