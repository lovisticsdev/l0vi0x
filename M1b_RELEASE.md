# M1b Release — verifier and evidence integrity

M1b implements V01–V09 as a deterministic, fail-closed verifier layer. It deliberately does not introduce LLM adapters, routing, P0–P4 agent work, V10–V13, or submission/report generation.

## V01–V09 boundary

| Check | Implementation | Hard/soft | Primary evidence |
|---|---|---|---|
| V01 | `verifier/eligibility.py` | hard | `Scope`, `Hypothesis`, `KnownIssue` |
| V02 | `verifier/span_check.py` | hard | pinned checkout + line-range SHA-256 |
| V03 | `verifier/pipeline.py` | hard | Forge build + verified tool lock |
| V04 | `verifier/pipeline.py` | hard | host-issued `ReplayCertificate`, 3 fresh-copy traces, environment hashes, control hashes, raw artifact paths |
| V05 | `verifier/cheatcode_policy.py` | hard | structured trace + canonical cheatcode catalog/policy + sanitized Foundry config |
| V06 | `verifier/assertion_extract.py` | hard | declared `WitnessAssertion`, observed `AssertionChecked`, control-run evidence |
| V07 | `verifier/harness_integrity.py` | hard | harness/source/runtime hashes, wrapper callsite/depth, CREATE2 evidence where supplied, event emitter/caller, actor/token coverage, transfer/snapshot consistency |
| V08 | `verifier/duplicate.py` | soft/human | exact/near duplicate result |
| V09 | `verifier/econ_check.py` | mixed | capital, gas, realism, sensitivity, head replay, independent-provider state |

## Routing

`NONDETERMINISTIC_ENV` routes back to investigation/pinning repair. `NONDETERMINISTIC_TRACE` parks the hypothesis with `characterize_conditional_trigger`. Fixable V05–V07 and production replay configuration failures route `CONFIRMED -> INVESTIGATING` rather than closing the hypothesis. Exact known issues close as `CLOSED_DUPLICATE`; out-of-scope or unrecoverable span drift closes. Soft duplicate/fragility signals retain a human-review route.

## Acceptance

```bash
make m0-acceptance
make m1a-acceptance
make m1b-acceptance
```

M1b acceptance is deterministic verifier acceptance. It does not replace M1a's live local/fork acceptance; M1a must still demonstrate real Foundry/gate execution before the combined M1 milestone can be declared complete.

## Fail-closed rules

- Empty or `verify-required` tool locks are failures, never success.
- Missing structured trace is not downgraded to textual trace evidence.
- `hoax`/`startHoax` is not accepted as an opaque compound event; the underlying state-mutation and impersonation calls must be visible in structured evidence.
- Harness runtime and wrapper callsite hashes are mandatory for V07.
- Certificate verification binds the witness hash, environment hash, observed-record aggregate, current trace-policy hash, and control-run hash.
- V01–V07 short-circuit on hard failure. V08 remains soft/human. V09 runs after V08 and is hard only for production replay/state mismatches.
