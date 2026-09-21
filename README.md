# l0vi0x

Deterministic Web3 security-research agent foundation.

## Current release: M1b verifier-ready; M1 overall acceptance still gated on live M1a

M0 is frozen. M1a provides the deterministic execution boundary, and M1b now provides the deterministic V01–V09 verifier/evidence-integrity layer:

- typed argv-only external-tool wrappers with bounded/recorded output in `tool_runs/`;
- fail-closed Foundry configuration sanitization (`ffi=false`, empty filesystem permissions, pinned gate URL, restricted config keys);
- authenticated allowlisted RPC gate with separate `/agent` and `/upstream` policies, upstream admin/write hard-deny, redacted parameters, status and latency logging;
- host/gate/sandbox separation with no sandbox certificate key;
- local-deployment and deployed-fork Foundry fixtures;
- CREATE2 witness-template deployment using the declared salt/deployer fields;
- structured trace extraction only from tool-produced JSON; human-readable trace text is never accepted as evidence;
- cumulative `warp`/`roll` enforcement across the complete trace;
- witness/environment hashing and assertion-kind validation;
- three fresh replay copies followed by host-side HMAC certificate issuance;
- explicit fail-closed M1a acceptance when Foundry/Anvil or the verified tool lock is missing;
- V01–V09 verifier pipeline with hard-fail ordering, deterministic failure routing, harness/economic integrity checks, duplicate review routing, and pinned-block severity basis.

## Acceptance

Run this sequence on the pinned engineering machine/CI image:

```bash
set -e
make setup
make test
make policy-test
make schemas
make cheatcode-catalog
make tools-update
make tools-verify
make m1a-acceptance
```

`make tools-update` records the installed binary version/probe output, resolved path and SHA-256. `solc-select` is probed with its supported `versions` command instead of an unsupported `--version` flag. It is intentionally impossible to hand-edit an incomplete lock into a passing state.

`make m1a-acceptance` is the real integration gate. It does not use `CallableReplayExecutor`; it requires the actual Foundry/Anvil toolchain and refuses to certify a run if Foundry JSON does not expose a structured trace object. Human-readable `-vvvv*` traces are never parsed as evidence.

`make schemas` is verification-only; `make schemas-generate` is the explicit regeneration command.

## M1b

M1b implements V01–V09 and their fail-closed acceptance fixtures. It consumes the M1a `TraceSummary`, verified structured-trace adapter, `ReplayCoordinator`, `FoundryReplayExecutor`, witness hashing, sanitized Foundry config, RPC-gate logs, and raw replay artifacts without bypassing the typed runner or replay/certificate boundary.

The combined M1 milestone is **not** declared complete until `make m1a-acceptance` passes against a real local fixture and real pinned fork fixture.
