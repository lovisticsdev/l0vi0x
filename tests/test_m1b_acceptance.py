from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_m1b_meta_paths_are_host_relative():
    """collection.json is written by the in-container `collect` phase (where the
    task dir is bind-mounted at /workspace/task) and read back by the host-side
    `certify`/`probes` phases (where the same directory is the host work root).
    The encode/normalize helpers must round-trip paths across that boundary
    instead of leaking container-absolute paths that don't exist on the host.
    """
    from l0vi0x.driver import m1b_acceptance

    host_root = ROOT / "eval/private/m1b-acceptance"
    sandbox_root = Path("/workspace/task")
    run_dir = sandbox_root / "replays/abc/run-1-xyz/repo"
    replay_root = sandbox_root / "replays/abc"

    # Written from inside the sandbox container: paths are absolute under
    # /workspace/task and must be encoded relative to that mount point.
    assert m1b_acceptance._encode_work_path(run_dir, host_root) == "replays/abc/run-1-xyz/repo"
    assert m1b_acceptance._encode_work_path(replay_root, host_root) == "replays/abc"

    # Read back on the host: the same relative strings must resolve under the
    # host's own work root, not the (nonexistent, on-host) /workspace/task.
    assert m1b_acceptance._normalize_meta_path("replays/abc/run-1-xyz/repo", host_root) == host_root / "replays/abc/run-1-xyz/repo"
    assert m1b_acceptance._normalize_meta_path("replays/abc", host_root) == host_root / "replays/abc"

    # A path already recorded as container-absolute (e.g. from an older run,
    # or a stale collection.json) must still be rehomed under host_root rather
    # than treated as a literal, unreachable /workspace/task path.
    assert m1b_acceptance._normalize_meta_path(run_dir, host_root) == host_root / "replays/abc/run-1-xyz/repo"
    assert m1b_acceptance._normalize_meta_path(replay_root, host_root) == host_root / "replays/abc"