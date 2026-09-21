from __future__ import annotations

import os
from pathlib import Path


ALLOWED_ENV = {"PATH", "HOME", "FOUNDRY_PROFILE", "FOUNDRY_FUZZ_RUNS", "FOUNDRY_FUZZ_SEED", "FOUNDRY_VERBOSITY", "SOLC_VERSION", "GATE_URL"}


def main() -> int:
    leaked = sorted(k for k in os.environ if k.upper() not in ALLOWED_ENV and any(x in k.upper() for x in ("KEY", "TOKEN", "SECRET", "PASSWORD", "RPC", "MNEMONIC")))
    if leaked:
        print("refusing sandbox due to secret-like environment variables", leaked)
        return 77
    root = Path(os.getcwd()).resolve()
    if not os.access(root, os.W_OK):
        # Read-only project roots are expected; writable task directories are supplied explicitly.
        pass
    print("l0vi0x sandbox ready; use typed tool wrappers")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
