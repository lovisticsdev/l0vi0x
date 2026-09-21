from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
from typing import Any, Callable, Protocol

from l0vi0x.core.certificates import issue_from_file
from l0vi0x.core.models import ReplayCertificate, Witness
from l0vi0x.chain.foundry_trace import extract_structured_trace
from l0vi0x.chain.trace import TraceSummary, enforce_cheatcode_policy, enforce_time_block_limits, parse_trace
from l0vi0x.chain.witness import witness_hash
from l0vi0x.tools.forge import test as forge_test


@dataclass(frozen=True, slots=True)
class ReplayRun:
    index: int
    passed: bool
    raw_trace: str
    control_sha256: str
    structured: TraceSummary
    environment_hash: str
    artifact_dir: str


class ReplayExecutor(Protocol):
    def execute(self, *, witness: Witness, copy_root: Path, run_index: int) -> dict[str, Any]: ...


class CallableReplayExecutor:
    """Testing-only executor; never used by the M1a acceptance command."""
    def __init__(self, fn: Callable[..., dict[str, Any]]) -> None:
        self.fn = fn

    def execute(self, *, witness: Witness, copy_root: Path, run_index: int) -> dict[str, Any]:
        return self.fn(witness=witness, copy_root=copy_root, run_index=run_index)


class FoundryReplayExecutor:
    """Run the pinned Foundry witness and return only tool-produced artifacts.

    The executor never receives the certificate key. The certificate is issued separately
    by the host-side certifier after all three fresh-copy executions have passed.
    """

    def __init__(self, *, forge_bin: str = "forge", tool_runs_dir_name: str = "tool_runs", env: dict[str, str] | None = None, trace_schema_id: str | None = None) -> None:
        self.forge_bin = forge_bin
        self.tool_runs_dir_name = tool_runs_dir_name
        self.env = dict(env or {})
        self.trace_schema_id = trace_schema_id

    def execute(self, *, witness: Witness, copy_root: Path, run_index: int) -> dict[str, Any]:
        tool_runs=copy_root/self.tool_runs_dir_name; tool_runs.mkdir(parents=True,exist_ok=True)
        output_dir=copy_root/"artifacts"/f"run-{run_index}"; output_dir.mkdir(parents=True,exist_ok=True)
        build = forge_test(
            root=copy_root,
            test_file=witness.test_file,
            test_name=witness.test_name,
            forge_bin=self.forge_bin,
            tool_runs_dir=tool_runs,
            verbosity=5,
            json_output=True,
            env=self.env,
        )
        (output_dir/"forge.stdout").write_text(build.stdout, encoding="utf-8")
        (output_dir/"forge.stderr").write_text(build.stderr, encoding="utf-8")
        if not build.passed:
            raise RuntimeError(f"forge witness failed on run {run_index}: {build.stderr or build.stdout}")
        structured = extract_structured_trace(build.json_result, expected_schema=self.trace_schema_id)
        trace_raw=json.dumps(structured,sort_keys=True,separators=(",",":"))
        (output_dir/"trace.json").write_text(trace_raw, encoding="utf-8")

        control = forge_test(
            root=copy_root,
            test_file=witness.test_file,
            test_name=witness.control_test_name,
            forge_bin=self.forge_bin,
            tool_runs_dir=tool_runs,
            verbosity=5,
            json_output=True,
            env=self.env,
        )
        (output_dir/"control.stdout").write_text(control.stdout, encoding="utf-8")
        (output_dir/"control.stderr").write_text(control.stderr, encoding="utf-8")
        if not control.passed:
            raise RuntimeError(f"forge control failed on run {run_index}: {control.stderr or control.stdout}")
        control_sha=hashlib.sha256((control.stdout+"\n"+control.stderr).encode()).hexdigest()
        (output_dir/"control.sha256").write_text(control_sha, encoding="utf-8")
        return {"passed":True,"trace_json":structured,"control_sha256":control_sha,"environment_hash":witness.env_hash,"artifact_dir":str(output_dir)}


class ReplayCoordinator:
    def __init__(self, *, repo_root: str | Path, replay_root: str | Path, executor: ReplayExecutor, cheatcode_catalog: dict[str, str], cheatcode_policy: dict[str, Any]) -> None:
        self.repo_root=Path(repo_root).resolve(); self.replay_root=Path(replay_root).resolve(); self.executor=executor; self.cheatcode_catalog=cheatcode_catalog; self.cheatcode_policy=cheatcode_policy

    def run(self, witness: Witness, *, runs: int = 3, audit_id: str, key_path: str | Path | None = None, key: bytes | None = None, certificate_id: str = "CERT-001") -> ReplayCertificate:
        if runs < 3: raise ValueError("replay certificate requires >=3 runs")
        if key_path is None and key is None: raise ValueError("host certificate key is required")
        root=self.replay_root/witness_hash(witness); root.mkdir(parents=True,exist_ok=True)
        replay_runs=[]
        for index in range(1,runs+1):
            copy_root=Path(tempfile.mkdtemp(prefix=f"run-{index}-",dir=root))
            shutil.copytree(self.repo_root,copy_root/"repo",dirs_exist_ok=True,ignore=shutil.ignore_patterns(".git",".venv","audits","__pycache__",".pytest_cache"))
            result=self.executor.execute(witness=witness,copy_root=copy_root/"repo",run_index=index)
            trace_raw=result.get("trace_json")
            if not isinstance(trace_raw,(str,bytes,dict,list)): raise ValueError("executor must return structured trace_json")
            trace_obj=parse_trace(trace_raw,cheatcode_catalog=self.cheatcode_catalog)
            enforce_time_block_limits(trace_obj,max_time_advance_s=witness.max_time_advance_s,max_block_advance=witness.max_block_advance)
            enforce_cheatcode_policy(trace_obj,witness_class=witness.witness_class,policy=self.cheatcode_policy)
            control_sha256=str(result.get("control_sha256",""));
            if not control_sha256: raise ValueError("control_sha256 is required")
            observed_env_hash=str(result.get("environment_hash",witness.env_hash))
            passed=bool(result.get("passed",False))
            artifact_dir=copy_root/"artifacts"; artifact_dir.mkdir(parents=True,exist_ok=True)
            rendered_trace=trace_raw if isinstance(trace_raw,str) else json.dumps(trace_raw,sort_keys=True,indent=2)
            (artifact_dir/"normalized-trace.json").write_text(rendered_trace,encoding="utf-8")
            (artifact_dir/"environment.sha256").write_text(observed_env_hash,encoding="utf-8")
            replay_runs.append(ReplayRun(index,passed,rendered_trace,control_sha256,trace_obj,observed_env_hash,str(artifact_dir)))
        if not all(run.passed for run in replay_runs): raise ValueError("not all replay runs passed")
        observed=[r.structured.observed_records_sha256() for r in replay_runs]
        if len({r.environment_hash for r in replay_runs}) != 1: raise ValueError("NONDETERMINISTIC_ENV")
        if len(set(observed)) != 1: raise ValueError("NONDETERMINISTIC_TRACE")
        controls={r.control_sha256 for r in replay_runs}
        if len(controls) != 1: raise ValueError("CONTROL_NONDETERMINISTIC")
        records_sha=hashlib.sha256(json.dumps(observed,separators=(",",":")).encode()).hexdigest()
        trace_policy_sha=hashlib.sha256(json.dumps({"catalog":self.cheatcode_catalog,"policy":self.cheatcode_policy},sort_keys=True,separators=(",",":")).encode()).hexdigest()
        if key_path is not None:
            key_path=Path(key_path).resolve()
            if key_path.is_relative_to(self.repo_root) or key_path.is_relative_to(self.replay_root):
                raise ValueError("certificate key must remain outside repository and replay roots")
            return issue_from_file(key_path,certificate_id=certificate_id,witness_sha256=witness_hash(witness),env_hash=witness.env_hash,runs=runs,observed_records_sha256=records_sha,trace_policy_sha256=trace_policy_sha,control_sha256=next(iter(controls)))
        # Bytes are retained only for unit tests; production acceptance uses key_path.
        from l0vi0x.core.certificates import issue
        return issue(key,certificate_id=certificate_id,witness_sha256=witness_hash(witness),env_hash=witness.env_hash,runs=runs,observed_records_sha256=records_sha,trace_policy_sha256=trace_policy_sha,control_sha256=next(iter(controls)))
