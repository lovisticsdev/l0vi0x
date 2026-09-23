# M1b acceptance gate

M1b is the evidence-integrity gate for a real replay-backed finding. Unit tests validate individual V01–V09 predicates; the acceptance driver validates that those predicates are fed by retained execution artifacts rather than caller-constructed evidence.

## Trust model

```text
HOST
  m1b_acceptance.py --phase certify
  HostCertifier
  host-only signing key

SANDBOX
  Foundry build/test
  structured trace extraction
  control replay
  environment observation
  retained raw artifacts

GATE
  authenticated /agent RPC boundary
  allowlisted read/simulation methods only

ANVIL
  isolated local execution chain
```

The sandbox never receives the certificate signing key. The certificate is issued only after the host verifier independently derives V04–V09 evidence from the retained replay roots.

## Required flow

```text
fixture declaration
  -> bootstrap identity
  -> source/build verification
  -> fresh replay #1
  -> fresh replay #2
  -> fresh replay #3
  -> V01–V09 derived verification
  -> host certificate issuance
  -> certificate-backed V01–V09 verification
  -> adversarial tamper probes
```

Every replay root must contain exactly one run artifact directory with:

- `trace.json` + `trace.sha256`
- `control.json` + `control.sha256`
- `control-trace.json` + `control-trace.sha256`
- `environment.json` + `environment.sha256`
- sanitized Foundry configuration
- retained tool-run records

V04 re-parses these artifacts and recomputes the hashes. A caller-supplied `ReplayEvidence` hash is not authoritative.

V06 derives control evidence from the retained control trace. V07 derives harness identity and coverage from the observed CREATE2 frame, source/artifact hashes, assertion context, and exact event counts. V09 derives economics from the harness economic snapshot, actual gas/gas-price evidence, token decimals, protocol-side delta, prices, and required sensitivity points.

## Real fixture corpus

`tests/fixtures/m1b_foundry/` contains:

- `OracleExploitWitness.t.sol` — positive oracle-manipulation extraction witness
- `BenignTwin.t.sol` — no-assertion control case
- `CheatExploitWitness.t.sol` — policy-violating witness
- `test/lib/EconHarness.sol` — canonical economic harness pattern
- `test/Create2HarnessFactory.sol` — pinned CREATE2 wrapper/deployer boundary

The acceptance driver additionally generates tamper cases for forged assertion data, forged assertion events, text-only trace imitation, environment drift, wrapper source tampering, actor/token omission, and false control-state mutation.

## Commands

```bash
make tools-verify
make m1b-unit
make m1b-acceptance
```

`make m1b-acceptance` requires Docker and a working verified Foundry tool lock. The current CI/container environment used for static review did not contain Foundry/Anvil and could not complete the live acceptance run.
