# M0–M1b engineering audit status

Audit date: 2026-09-21

## Executive result

**M0: code/test acceptance surface is implemented.**

**M1b: V01–V09 verifier implementation and deterministic verifier fixtures are implemented.**

**M1a: NOT ACCEPTED.** The repository is not certifiable as M0–M1b complete until the required live Foundry/Anvil/gate acceptance has been run successfully.

The authoritative build-plan acceptance rows are:

- **M0:** `make test` passes lifecycle, ladder, task-idempotency, redaction, sandbox and policy tests; `blocked_on_human` exists in the task DDL; JSON Schemas are generated from models.
- **M1a:** local and fork fixtures produce valid 3-run certificates; denied agent/upstream RPC methods are refused and logged; cumulative small `warp`/`roll` advances exceeding the declared limit are rejected.
- **M1b:** V01–V09 acceptance fixtures pass; cheatcode wrappers, forged `AssertionChecked`, trace-text imitation and tampered harnesses fail closed; V04 distinguishes environment from trace nondeterminism; fixable verifier failures route through `CONFIRMED → INVESTIGATING`; severity uses pinned-block figures.

## Current repository status

The working tree contains the M1a trace-adapter, environment-observation, RPC-policy, Foundry-config and verifier changes reviewed during this audit. Important source-level defects found during the review were corrected, including:

- wrong `AssertionChecked` ABI signature;
- non-authoritative/dead Foundry adapter path in the replay executor;
- iterator-consuming Foundry-log comparison;
- failure to propagate the pinned fork block into V05 policy enforcement;
- replay executors being permitted to omit independent environment hashes;
- environment nondeterminism being masked by an immediate declaration mismatch;
- fork fixture target reference left unset;
- stale RPC-policy unit tests after the endpoint schema changed.

The verifier now requires observed assertion values and evaluates the declared assertion operator rather than assuming the event ABI carries an operator field.

## What is still not accepted

1. `config/tools.lock.yaml` is still `verify-required` with no entries in the supplied repository. A verified nine-tool lock cannot be fabricated without the pinned binaries.
2. `forge`, `anvil`, and `solc` are not installed in this execution environment, so the required real Foundry acceptance cannot be executed here.
3. `driver/m1a_acceptance.py` still contains placeholder witness metadata and requires further integration work before it can produce honest local/fork certificates.
4. The fork fixture requires complete alias-based gate configuration and real fork execution before its trace/environment binding can be certified.
5. V07 still requires real harness/runtime/source/depth evidence from the M1a pipeline; deterministic synthetic verifier tests do not replace that integration.

## Local test evidence

The repository test suite passes in this container after applying an **external, test-only Keccak implementation** because the locked `eth-hash` package is unavailable locally. The shim is not part of the repository and was not used as evidence that the packaging/dependency lock is satisfied.

Schema drift check passes.

The actual M1a acceptance driver currently fails closed with the expected tooling gate:

```text
M1a acceptance: BLOCKED/FAIL
M1a acceptance requires installed forge; run make tools-update after installing pinned tooling
```

This document intentionally does **not** claim M1a or combined M0–M1b acceptance.
