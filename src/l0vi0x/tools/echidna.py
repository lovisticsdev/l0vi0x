from __future__ import annotations

from l0vi0x.tools.runner import run
from l0vi0x.tools.medusa import FuzzReport


def fuzz(*, root, config="echidna.yaml", echidna_bin="echidna", timeout_s=900, tool_runs_dir=None) -> FuzzReport:
    result = run([echidna_bin, str(root), "--config", config], cwd=root, timeout_s=timeout_s, tool_runs_dir=tool_runs_dir)
    if result.rc != 0:
        raise RuntimeError(result.stderr or result.stdout)
    return FuzzReport([], {}, {"stdout": result.stdout})
