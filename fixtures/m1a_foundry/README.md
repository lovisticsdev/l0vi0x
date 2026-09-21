# M1a Foundry fixtures

These fixtures are deterministic smoke/acceptance projects for the M1a execution boundary. They do not contain production findings.

- `LocalDeploymentWitness.t.sol` deploys the target and harness locally, uses a CREATE2 harness factory, and exercises cumulative time/block advancement.
- `DeployedForkWitness.t.sol` selects a pinned fork through the `GATE_URL` alias; the host-side acceptance harness should point the gate Anvil at a fixture upstream Anvil containing the target deployment.

The Python acceptance path refuses to certify any run unless Forge exposes a structured trace object in its JSON output. Human-readable `-vvvv*` output is never parsed as evidence.
