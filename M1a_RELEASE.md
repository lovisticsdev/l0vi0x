# M1a implementation status

This repository contains the M1a execution/replay implementation work, but M1a is **not an accepted release**.

Acceptance still requires the build-plan live evidence: local and fork fixtures must each yield a valid three-run certificate, RPC denials must be observed and logged, and cumulative `warp`/`roll` limits must fail closed.

The committed tool lock is currently `verify-required` in the supplied repository and must be regenerated on the pinned toolchain host with `make tools-update`. No tool version or hash is fabricated in this source tree.
