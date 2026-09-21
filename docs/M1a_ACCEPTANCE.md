# M1a acceptance gate

The M1a gate is intentionally deterministic and tool-backed.

1. `make tools-update` must run on the pinned engineering host and produce a complete `config/tools.lock.yaml`.
2. `make tools-verify` must pass before any witness execution.
3. The local and deployed-fork fixtures are run by `FoundryReplayExecutor`, never `CallableReplayExecutor`. For the fork fixture, `GATE_URL` must point at the authenticated agent endpoint of the gate stack.
4. Each fixture is executed three times from fresh copies.
5. The structured trace parser accepts only JSON trace records supplied by the Foundry adapter. Human-readable trace text cannot certify anything.
6. Cumulative `warp` and `roll` deltas are enforced across the entire structured trace.
7. `/agent` and `/upstream` RPC requests are authenticated, allowlisted, logged, and redacted; admin/write methods are hard-denied even if an allowlist is broadened.
8. The replay signing key remains outside the copied repository/replay roots. Certificate issuance occurs only after all deterministic checks pass.

The current repository intentionally leaves the tool lock in `verify-required` state because this environment does not contain Foundry/Anvil. That is a release-blocking installation prerequisite, not a fabricated version entry.
