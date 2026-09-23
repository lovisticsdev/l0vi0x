# M1a acceptance gate

M1a is the deterministic execution-boundary milestone. The acceptance path uses Docker for the gate/sandbox trust zones and the typed tool wrappers for Forge execution.

1. `make tools-update` is run on the pinned engineering host when the lock changes; `make tools-verify` must pass before acceptance.
2. The gate stack provides an isolated Anvil node plus an authenticated `/agent` RPC boundary. Target-touching Foundry work runs in the sandbox container.
3. Local and deployed-fork fixtures are executed by `FoundryReplayExecutor`, never `CallableReplayExecutor` in acceptance.
4. Each fixture is executed three times from source-only fresh copies. Prior `out/`, `cache/`, `.git/`, Python caches, prior artifacts, and tool-run state are excluded from the copied source tree.
5. Structured trace records are the only evidence source. Human-readable Forge trace text cannot certify a replay.
6. Cumulative `warp` and `roll` deltas are enforced across the complete structured trace.
7. `/agent` and upstream RPC requests are authenticated, allowlisted, logged, and redacted; admin/write methods are hard-denied even if an allowlist is broadened.
8. CREATE2 identity, harness source/runtime hashes, wrapper source/runtime hashes, and the deployment/environment binding are retained as replay evidence.
9. The replay signing key remains outside replay roots. M1a certification occurs only after the deterministic collection checks pass.

The Dockerfiles and compose configuration are the acceptance path; the older host-only Anvil path is not used by the milestone gate.
