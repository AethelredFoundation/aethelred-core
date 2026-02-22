# Verify Keeper Architecture

This document defines the production responsibility split for `x/verify/keeper`.

## Scope

The verify keeper is the chain-side verification orchestration layer. It does:

- zkML proof verification path selection and execution
- TEE attestation verification path selection and execution
- circuit-breaker-backed remote verification
- verification key and circuit registry management
- module params/genesis import-export for deterministic state

It does **not** execute model inference or consensus vote aggregation directly.

## File Responsibilities

- `keeper.go`: keeper wiring, constructor, authority, and shared dependencies
- `http_security.go`: outbound HTTP hardening (endpoint validation, bounded reads, secure client defaults)
- `zk_verification_path.go`: zkML verification flow orchestration
- `tee_verification_path.go`: TEE verification flow orchestration
- `remote_verifier.go`: remote verifier transport adapters
- `registry_genesis.go`: key/circuit registries and genesis lifecycle
- `zk_verifier.go`: protocol/system-specific zk verifier implementations

## Production Guarantees

- Fail-closed behavior when verification endpoints are invalid or unavailable
- SSRF-resistant endpoint policy with local/private network rejection
- Circuit breaker protection for all remote verifier paths
- Deterministic key/circuit registry persistence through module store + genesis

## Testing Strategy

- `zk_verifier_test.go`: proof-system and proof-shape checks
- `remote_verifier_test.go`: remote verifier success/failure scenarios
- `circuit_breaker_test.go`: breaker transitions, concurrency, and overload protection

Tests are written to run in restricted CI/sandbox environments without requiring socket binding.
