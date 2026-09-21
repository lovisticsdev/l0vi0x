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
from l0vi0x.chain.foundry_trace import adapt_forge_test_json
from l0vi0x.chain.trace import TraceSummary, enforce_cheatcode_policy, enforce_time_block_limits, parse_trace
from l0vi0x.chain.witness import witness_hash
from l0vi0x.chain.environment import observe_tree, environment_hash, initial_block_env_from_config
from l0vi0x.tools.lock import version_text
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

    def _initial_environment(self, copy_root: Path, witness: Witness) -> tuple[int, int]:
        if witness.witness_class == "local_deployment":
            return initial_block_env_from_config(copy_root)
        raw_block = self.env.get("L0VI0X_INITIAL_BLOCK")
        raw_timestamp = self.env.get("L0VI0X_INITIAL_TIMESTAMP")
        if raw_block is None or raw_timestamp is None:
            raise RuntimeError("deployed_fork replay requires independently observed initial block/timestamp")
        try:
            block = int(raw_block, 0)
            timestamp = int(raw_timestamp, 0)
        except ValueError as exc:
            raise RuntimeError("invalid replay initial block/timestamp") from exc
        return timestamp, block

    def execute(self, *, witness: Witness, copy_root: Path, run_index: int) -> dict[str, Any]:
        return self.fn(witness=witness, copy_root=copy_root, run_index=run_index)


class FoundryReplayExecutor:
    """Run the pinned Foundry witness and return only tool-produced artifacts.

    The executor never receives the certificate key. The certificate is issued separately
    by the host-side certifier after all three fresh-copy executions have passed.
    """

    def __init__(
        self,
        *,
        forge_bin: str = "forge",
        tool_runs_dir_name: str = "tool_runs",
        env: dict[str, str] | None = None,
        trace_schema_id: str | None = None,
        harness_library_paths: tuple[str, ...] = (),
        deployment_plan_paths: tuple[str, ...] = (),
    ) -> None:
        self.forge_bin = forge_bin
        self.tool_runs_dir_name = tool_runs_dir_name
        self.env = dict(env or {})
        self.trace_schema_id = trace_schema_id
        self.harness_library_paths = harness_library_paths
        self.deployment_plan_paths = deployment_plan_paths

    def _initial_environment(self, copy_root: Path, witness: Witness) -> tuple[int, int]:
        if witness.witness_class == "local_deployment":
            return initial_block_env_from_config(copy_root)
        raw_block = self.env.get("L0VI0X_INITIAL_BLOCK")
        raw_timestamp = self.env.get("L0VI0X_INITIAL_TIMESTAMP")
        if raw_block is None or raw_timestamp is None:
            raise RuntimeError("deployed_fork replay requires independently observed initial block/timestamp")
        try:
            block = int(raw_block, 0)
            timestamp = int(raw_timestamp, 0)
        except ValueError as exc:
            raise RuntimeError("invalid replay initial block/timestamp") from exc
        return timestamp, block

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
        if not isinstance(build.json_result, dict):
            raise RuntimeError("Forge did not return JSON test results")
        initial_timestamp, initial_block = self._initial_environment(copy_root, witness)
        structured = adapt_forge_test_json(
            build.json_result,
            test_file=witness.test_file,
            test_name=witness.test_name,
            initial_timestamp=initial_timestamp,
            initial_block=initial_block,
        )
        if self.trace_schema_id is not None and structured["l0vi0x_structured_trace"]["schema"] != self.trace_schema_id:
            raise RuntimeError("Foundry adapter schema does not match the requested trace schema")
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
        observation = observe_tree(
            copy_root,
            test_file=witness.test_file,
            witness_class=witness.witness_class,
            harness_library_paths=self.harness_library_paths,
            deployment_plan_paths=self.deployment_plan_paths,
        )
        try:
            forge_version = version_text(self.forge_bin, name="forge")[0]
        except Exception as exc:
            raise RuntimeError(f"cannot independently observe forge version: {exc}") from exc
        observed_env = environment_hash(
            observation, witness, {"forge": forge_version},
            initial_timestamp=initial_timestamp,
            initial_block=initial_block,
        )
        return {"passed":True,"trace_json":structured,"control_sha256":control_sha,"environment_hash":observed_env,"artifact_dir":str(output_dir)}


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
            if "environment_hash" not in result:
                raise ValueError("executor must return an independently observed environment_hash")
            observed_env_hash=str(result["environment_hash"])
            passed=bool(result.get("passed",False))
            artifact_dir=copy_root/"artifacts"; artifact_dir.mkdir(parents=True,exist_ok=True)
            rendered_trace=trace_raw if isinstance(trace_raw,str) else json.dumps(trace_raw,sort_keys=True,indent=2)
            (artifact_dir/"normalized-trace.json").write_text(rendered_trace,encoding="utf-8")
            (artifact_dir/"environment.sha256").write_text(observed_env_hash,encoding="utf-8")
            replay_runs.append(ReplayRun(index,passed,rendered_trace,control_sha256,trace_obj,observed_env_hash,str(artifact_dir)))
        if not all(run.passed for run in replay_runs): raise ValueError("not all replay runs passed")
        observed=[r.structured.observed_records_sha256() for r in replay_runs]
        environment_hashes = {r.environment_hash for r in replay_runs}
        if len(environment_hashes) != 1:
            raise ValueError("NONDETERMINISTIC_ENV")
        observed_environment_hash = next(iter(environment_hashes))
        if observed_environment_hash != witness.env_hash:
            raise ValueError("ENV_DECLARATION_MISMATCH")
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
