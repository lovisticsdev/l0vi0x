from __future__ import annotations

import shutil
import os
from pathlib import Path
import subprocess
import sys
import pytest

ROOT=Path(__file__).resolve().parents[1]


def test_m1a_acceptance_command_is_fail_closed_without_verified_tooling():
    if shutil.which("forge") and shutil.which("anvil") and (ROOT/"config/tools.lock.yaml").read_text(encoding="utf-8").find("verify-required") < 0:
        pytest.skip("integration environment available; exercised by make m1a-acceptance")
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT / "src") + os.pathsep + env.get("PYTHONPATH", "")
    proc=subprocess.run([sys.executable,"-m","l0vi0x.driver.m1a_acceptance"],cwd=ROOT,env=env,capture_output=True,text=True,check=False)
    assert proc.returncode == 2
    assert "M1a acceptance:" in proc.stderr
