# l0vi0x

`l0vi0x` is a certificate-backed Solidity/EVM security-research execution and verification foundation. M0 supplies the event-first state/evidence layer. M1a supplies the deterministic Foundry replay boundary and RPC trust zones. M1b supplies the derived-evidence V01–V09 verifier and real acceptance corpus.

## Milestone status

M0: hardened implementation with append-only event history, event-first entity persistence, lifecycle/ladder prerequisites, redacted tool persistence, and schema drift checks.

M1a: implementation uses the Docker gate/sandbox boundary, fresh source-only replay copies, typed external-tool wrappers, pinned harness identity, and retained replay artifacts. Live acceptance requires a verified tool lock plus Docker/Foundry availability on the acceptance host.

M1b: real acceptance driver and fixtures are present. The verifier derives replay/control/harness/economic evidence from retained artifacts before certificate issuance. Unit verifier tests remain separate from the end-to-end acceptance gate.

## Core trust boundary

```text
source fixture
   |
   v
clean replay copy
   |
   +--> Foundry build/test --> structured trace
   +--> control replay -----> control trace
   +--> environment --------> environment hash
   +--> RPC gate -----------> observed gas price / state
   |
   v
retained replay roots
   |
   v
host V01–V09 derivation
   |
   +--> fail/reroute
   |
   v
host-only certificate issuance
```

The verifier does not treat caller-populated replay hashes, control booleans, harness fields, or economics objects as authoritative. Those objects are diagnostic representations; production verification re-derives them from retained artifacts.

## Acceptance commands

```bash
make tools-verify
make m0-acceptance
make m1a-acceptance
make m1b-unit
make m1b-acceptance
make audit-m0-m1b
```

`m1a-acceptance` and `m1b-acceptance` require Docker and the pinned Foundry toolchain. Static review environments may be unable to execute those live gates.

## M1b fixtures

`tests/fixtures/m1b_foundry/` contains the positive oracle-extraction witness, a benign twin, a policy-violating witness, the canonical economic harness, a CREATE2 wrapper, and fixture price evidence. The acceptance driver also creates adversarial replay mutations for integrity and anti-vacuity checks.

## Release hygiene

Generated `out/`, `cache/`, Python bytecode caches, pytest caches, egg-info directories, temporary evaluation archives, and runtime tool-run material are not part of a source release or fresh replay source copy.
