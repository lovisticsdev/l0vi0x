# M1b real acceptance fixture

This fixture is a real Foundry execution corpus for the V04/V05/V06/V07/V09 trust boundary.

`OracleExploitWitness.t.sol` contains the positive economic witness. The vulnerable path is an oracle-price-dependent borrow in `LendingPool.sol`. The witness uses the canonical economic harness and a CREATE2-deployed harness controlled by `Create2HarnessFactory`.

`BenignTwin.t.sol` is a non-exploiting twin with zero borrow capacity. `CheatExploitWitness.t.sol` is a negative policy fixture that calls `deal` from the witness and must be rejected by the witness-phase cheatcode policy.

No generated `out/`, `cache/`, `artifacts/`, or `tool_runs/` directories are source inputs; the replay driver creates them in fresh copies.
