from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
from typing import Any, Callable, Protocol

from l0vi0x.chain.environment import (
    environment_hash,
    initial_block_env_from_config,
    observe_tree,
)
from l0vi0x.chain.foundry_config import sanitize_foundry_config
from l0vi0x.chain.foundry_trace import (
    CANONICAL_TRACE_SCHEMA,
    adapt_forge_test_json,
    extract_structured_trace,
)
from l0vi0x.chain.trace import (
    TraceSummary,
    enforce_cheatcode_policy,
    enforce_time_block_limits,
    parse_trace,
)
from l0vi0x.chain.witness import witness_hash
from l0vi0x.core.models import Witness
from l0vi0x.core.redaction import redact
from l0vi0x.tools.forge import (
    build as forge_build,
    test as forge_test,
)
from l0vi0x.tools.runner import run as run_tool


def _strip_wall_clock_duration(obj: Any) -> None:
    if isinstance(obj, dict):
        obj.pop("duration", None)
        for value in obj.values():
            _strip_wall_clock_duration(value)
    elif isinstance(obj, list):
        for item in obj:
            _strip_wall_clock_duration(item)


def _canonical_hash(payload: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        ).encode("utf-8")
    ).hexdigest()


@dataclass(frozen=True, slots=True)
class ReplayRun:
    index: int
    passed: bool
    artifact_dir: Path
    trace_path: Path
    control_path: Path
    control_trace_path: Path
    environment_path: Path
    control_sha256: str
    environment_hash: str
    structured: TraceSummary


@dataclass(frozen=True, slots=True)
class ReplayCollection:
    witness_hash: str
    root: Path
    runs: tuple[ReplayRun, ...]
    observed_records_sha256: str
    trace_policy_sha256: str
    control_sha256: str
    environment_hash: str


class ReplayExecutor(Protocol):
    def execute(
        self,
        *,
        witness: Witness,
        copy_root: Path,
        run_index: int,
    ) -> dict[str, Any]:
        ...


class CallableReplayExecutor:
    """Testing-only executor; it does not issue certificates."""

    def __init__(
        self,
        fn: Callable[..., dict[str, Any]],
    ) -> None:
        self.fn = fn

    def execute(
        self,
        *,
        witness: Witness,
        copy_root: Path,
        run_index: int,
    ) -> dict[str, Any]:
        return self.fn(
            witness=witness,
            copy_root=copy_root,
            run_index=run_index,
        )


class FoundryReplayExecutor:
    def __init__(
        self,
        *,
        forge_bin: str = "forge",
        tool_runs_dir_name: str = "tool_runs",
        env: dict[str, str] | None = None,
        trace_schema_id: str | None = None,
        harness_library_paths: tuple[str, ...] = (),
        deployment_plan_paths: tuple[str, ...] = (),
        foundry_policy_path: str | Path | None = None,
    ) -> None:
        self.forge_bin = forge_bin
        self.tool_runs_dir_name = tool_runs_dir_name
        self.env = dict(env or {})
        self.trace_schema_id = trace_schema_id
        self.harness_library_paths = harness_library_paths
        self.deployment_plan_paths = deployment_plan_paths
        self.foundry_policy_path = (
            Path(foundry_policy_path).resolve()
            if foundry_policy_path
            else None
        )

    def _initial_environment(
        self,
        copy_root: Path,
        witness: Witness,
    ) -> tuple[int, int]:
        if witness.witness_class == "local_deployment":
            return initial_block_env_from_config(
                copy_root
            )

        raw_block = self.env.get(
            "L0VI0X_INITIAL_BLOCK"
        )
        raw_timestamp = self.env.get(
            "L0VI0X_INITIAL_TIMESTAMP"
        )

        if raw_block is None or raw_timestamp is None:
            raise RuntimeError(
                "deployed_fork replay requires "
                "independently observed initial "
                "block/timestamp"
            )

        try:
            block = int(raw_block, 0)
            timestamp = int(raw_timestamp, 0)
        except ValueError as exc:
            raise RuntimeError(
                "invalid replay initial "
                "block/timestamp"
            ) from exc

        return timestamp, block

    def _tool_version(self) -> str:
        result = run_tool(
            [
                self.forge_bin,
                "--version",
            ],
            cwd=Path.cwd(),
            timeout_s=30,
        )

        if (
            result.rc != 0
            or not result.stdout.strip()
        ):
            raise RuntimeError(
                result.stderr.strip()
                or "forge --version failed"
            )

        return result.stdout.strip()

    def execute(
        self,
        *,
        witness: Witness,
        copy_root: Path,
        run_index: int,
    ) -> dict[str, Any]:
        tool_runs = (
            copy_root / self.tool_runs_dir_name
        )
        tool_runs.mkdir(
            parents=True,
            exist_ok=True,
        )

        output_dir = (
            copy_root
            / "artifacts"
            / f"run-{run_index}"
        )
        output_dir.mkdir(
            parents=True,
            exist_ok=True,
        )

        foundry_path = copy_root / "foundry.toml"

        sanitized = sanitize_foundry_config(
            foundry_path,
            foundry_path,
            compiler=witness.compiler,
            gate_url=self.env.get(
                "GATE_URL",
                "",
            ),
            policy_path=self.foundry_policy_path,
        )

        sanitized_path = (
            output_dir
            / "sanitized-foundry.json"
        )
        sanitized_path.write_text(
            json.dumps(
                sanitized,
                sort_keys=True,
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )

        build = forge_build(
            root=copy_root,
            forge_bin=self.forge_bin,
            tool_runs_dir=tool_runs,
        )

        (
            output_dir / "build.json"
        ).write_text(
            json.dumps(
                {
                    "passed": build.passed,
                    "returncode": build.returncode,
                    "stdout": redact(
                        build.stdout
                    ),
                    "stderr": redact(
                        build.stderr
                    ),
                },
                sort_keys=True,
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )

        if not build.passed:
            raise RuntimeError(
                f"forge build failed on run "
                f"{run_index}: "
                f"{build.stderr or build.stdout}"
            )

        (
            initial_timestamp,
            initial_block,
        ) = self._initial_environment(
            copy_root,
            witness,
        )

        build_test = forge_test(
            root=copy_root,
            test_file=witness.test_file,
            test_name=witness.test_name,
            forge_bin=self.forge_bin,
            tool_runs_dir=tool_runs,
            verbosity=5,
            json_output=True,
            env=self.env,
        )

        if not build_test.passed:
            raise RuntimeError(
                f"forge witness failed on run "
                f"{run_index}: "
                f"{build_test.stderr or build_test.stdout}"
            )

        if not isinstance(
            build_test.json_result,
            dict,
        ):
            raise RuntimeError(
                "Forge did not return JSON "
                "witness results"
            )

        structured_adapter = (
            adapt_forge_test_json(
                build_test.json_result,
                test_file=witness.test_file,
                test_name=witness.test_name,
                initial_timestamp=initial_timestamp,
                initial_block=initial_block,
            )
        )

        canonical_trace = (
            extract_structured_trace(
                structured_adapter,
                expected_schema=(
                    self.trace_schema_id
                    or CANONICAL_TRACE_SCHEMA
                ),
            )
        )

        trace_raw = json.dumps(
            canonical_trace,
            sort_keys=True,
            separators=(",", ":"),
        )

        trace_path = (
            output_dir / "trace.json"
        )
        trace_path.write_text(
            trace_raw,
            encoding="utf-8",
        )

        (
            output_dir / "trace.sha256"
        ).write_text(
            hashlib.sha256(
                trace_raw.encode("utf-8")
            ).hexdigest()
            + "\n",
            encoding="utf-8",
        )

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

        if not control.passed:
            raise RuntimeError(
                f"forge control failed on run "
                f"{run_index}: "
                f"{control.stderr or control.stdout}"
            )

        if not isinstance(
            control.json_result,
            dict,
        ):
            raise RuntimeError(
                "Forge did not return JSON "
                "control results"
            )

        control_obj = json.loads(
            json.dumps(
                control.json_result
            )
        )
        _strip_wall_clock_duration(
            control_obj
        )

        control_path = (
            output_dir / "control.json"
        )
        control_path.write_text(
            json.dumps(
                control_obj,
                sort_keys=True,
                separators=(",", ":"),
            ),
            encoding="utf-8",
        )

        control_sha = _canonical_hash(
            control_obj
        )

        (
            output_dir / "control.sha256"
        ).write_text(
            control_sha + "\n",
            encoding="utf-8",
        )

        control_adapter = (
            adapt_forge_test_json(
                control_obj,
                test_file=witness.test_file,
                test_name=witness.control_test_name,
                initial_timestamp=initial_timestamp,
                initial_block=initial_block,
            )
        )

        control_trace = (
            extract_structured_trace(
                control_adapter,
                expected_schema=(
                    self.trace_schema_id
                    or CANONICAL_TRACE_SCHEMA
                ),
            )
        )

        control_trace_path = (
            output_dir
            / "control-trace.json"
        )

        control_trace_raw = json.dumps(
            control_trace,
            sort_keys=True,
            separators=(",", ":"),
        )

        control_trace_path.write_text(
            control_trace_raw,
            encoding="utf-8",
        )

        (
            output_dir
            / "control-trace.sha256"
        ).write_text(
            hashlib.sha256(
                control_trace_raw.encode(
                    "utf-8"
                )
            ).hexdigest()
            + "\n",
            encoding="utf-8",
        )

        observation = observe_tree(
            copy_root,
            test_file=witness.test_file,
            witness_class=witness.witness_class,
            harness_library_paths=(
                self.harness_library_paths
            ),
            deployment_plan_paths=(
                self.deployment_plan_paths
            ),
        )

        tool_versions: dict[str, str] = {}

        for tool_name, argv in (
            (
                "forge",
                [
                    self.forge_bin,
                    "--version",
                ],
            ),
            (
                "anvil",
                [
                    "anvil",
                    "--version",
                ],
            ),
            (
                "cast",
                [
                    "cast",
                    "--version",
                ],
            ),
        ):
            version_result = run_tool(
                argv,
                cwd=copy_root,
                timeout_s=30,
                tool_runs_dir=tool_runs,
            )

            if (
                version_result.rc != 0
                or not version_result.stdout.strip()
            ):
                raise RuntimeError(
                    version_result.stderr.strip()
                    or (
                        "cannot observe "
                        f"{tool_name} version"
                    )
                )

            tool_versions[
                tool_name
            ] = version_result.stdout.strip()

        rpc_url = (
            self.env.get(
                "L0VI0X_RPC_URL"
            )
            or self.env.get(
                "GATE_URL"
            )
        )

        if not rpc_url:
            raise RuntimeError(
                "M1b economic replay requires "
                "a gated RPC URL for actual "
                "gas-price observation"
            )

        gas_price_result = run_tool(
            [
                "cast",
                "gas-price",
                "--rpc-url",
                rpc_url,
            ],
            cwd=copy_root,
            timeout_s=30,
            tool_runs_dir=tool_runs,
        )

        if gas_price_result.rc != 0:
            raise RuntimeError(
                gas_price_result.stderr.strip()
                or "cast gas-price failed"
            )

        gas_price_text = (
            gas_price_result.stdout
            .strip()
            .splitlines()[-1]
        )

        try:
            gas_price_wei = int(
                gas_price_text,
                0,
            )
        except ValueError:
            try:
                gas_price_wei = int(
                    gas_price_text
                )
            except ValueError as exc:
                raise RuntimeError(
                    "invalid observed gas price: "
                    f"{gas_price_text!r}"
                ) from exc

        if gas_price_wei < 0:
            raise RuntimeError(
                "negative gas price is impossible"
            )

        observed_env = environment_hash(
            observation,
            witness,
            tool_versions,
            initial_timestamp=initial_timestamp,
            initial_block=initial_block,
        )

        environment_path = (
            output_dir
            / "environment.json"
        )

        environment_path.write_text(
            json.dumps(
                {
                    "observation": (
                        observation.to_dict()
                    ),
                    "tool_versions": tool_versions,
                    "initial_timestamp": (
                        initial_timestamp
                    ),
                    "initial_block": initial_block,
                    "gas_price_wei": (
                        gas_price_wei
                    ),
                    "environment_hash": (
                        observed_env
                    ),
                },
                sort_keys=True,
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )

        (
            output_dir / "environment.sha256"
        ).write_text(
            observed_env + "\n",
            encoding="utf-8",
        )

        return {
            "passed": True,
            "trace_path": str(trace_path),
            "control_path": str(control_path),
            "control_trace_path": str(
                control_trace_path
            ),
            "environment_path": str(
                environment_path
            ),
            "control_sha256": control_sha,
            "environment_hash": observed_env,
            "artifact_dir": str(output_dir),
            "build_passed": build.passed,
        }


class ReplayCoordinator:
    def __init__(
        self,
        *,
        repo_root: str | Path,
        replay_root: str | Path,
        executor: ReplayExecutor,
        cheatcode_catalog: dict[str, str],
        cheatcode_policy: dict[str, Any],
    ) -> None:
        self.repo_root = (
            Path(repo_root).resolve()
        )
        self.replay_root = (
            Path(replay_root).resolve()
        )
        self.executor = executor
        self.cheatcode_catalog = (
            cheatcode_catalog
        )
        self.cheatcode_policy = (
            cheatcode_policy
        )

    @staticmethod
    def _copy_ignore(
        _directory: str,
        names: list[str],
    ) -> set[str]:
        """
        Exclude all generated, private, cache, and
        potentially host/container-owned material from
        the fresh replay source snapshot.

        In particular, `eval/` is deliberately excluded.
        Acceptance workspaces under `eval/private/` are
        mutable evidence stores and are not part of the
        immutable source snapshot used for replay.

        Excluding the complete `eval/` tree is preferable
        to excluding only `eval/private/`, because a replay
        must not inherit generated evaluation state from any
        previous acceptance run.
        """
        ignored_exact = {
            ".git",
            ".venv",
            ".mypy_cache",
            ".ruff_cache",
            ".pytest_cache",
            "__pycache__",
            "audits",
            "eval",
            "out",
            "cache",
            "tool_runs",
            "artifacts",
            "keys",
        }

        ignored_suffixes = (
            ".pyc",
            ".db",
            ".sqlite",
            ".sqlite3",
        )

        ignored = set()

        for name in names:
            if name in ignored_exact:
                ignored.add(name)
                continue

            if name.endswith(
                ignored_suffixes
            ):
                ignored.add(name)
                continue

            if name == ".env":
                ignored.add(name)
                continue

            if (
                name.startswith(".env.")
                and name != ".env.example"
            ):
                ignored.add(name)
                continue

            if name.endswith(
                ".pyc"
            ):
                ignored.add(name)

        return ignored

    @staticmethod
    def _widen_permissions(path: Path) -> None:
        """
        Recursively grant read (and execute, for directories) access to
        everyone under `path`.

        `collect` runs inside the sandboxed Foundry container as a fixed,
        non-root uid (uid 10001 "agent" in Dockerfile.sandbox). Every
        directory and file it creates on the bind-mounted SANDBOX_TASK_DIR
        therefore lands on the host owned by that uid, with whatever mode
        the container's umask happens to produce -- not guaranteed to be
        host-readable (tempfile.mkdtemp in particular hardcodes 0700, but
        plain mkdir()/copytree() calls further down the tree are just as
        opaque depending on umask). The host-side `certify` step reads this
        same tree as the invoking host user, a different uid with no
        special access, so a fix-up only on the top-level run directory is
        not enough -- anything created deeper (e.g. `repo/artifacts`) can
        still be unreadable.

        This tree holds replay/trace evidence, not secrets -- the audit
        signing key is asserted to live outside the repo/work roots (see
        certify()'s key_path check) -- so widening to host-readable here is
        safe.
        """
        if path.is_symlink():
            return
        if path.is_dir():
            path.chmod(
                path.stat().st_mode
                | 0o755
            )
            for child in path.iterdir():
                ReplayCoordinator._widen_permissions(
                    child
                )
        elif path.is_file():
            path.chmod(
                path.stat().st_mode
                | 0o644
            )

    def collect(
        self,
        witness: Witness,
        *,
        runs: int = 3,
        audit_id: str = "M1B",
    ) -> ReplayCollection:
        if runs < 3:
            raise ValueError(
                "replay collection requires "
                ">=3 fresh runs"
            )

        root = (
            self.replay_root
            / witness_hash(witness)
        )

        root.mkdir(
            parents=True,
            exist_ok=True,
        )

        replay_runs: list[ReplayRun] = []

        try:
            for index in range(
                1,
                runs + 1,
            ):
                run_root = Path(
                    tempfile.mkdtemp(
                        prefix=f"run-{index}-",
                        dir=root,
                    )
                )

                try:
                    copy_root = (
                        run_root / "repo"
                    )

                    shutil.copytree(
                        self.repo_root,
                        copy_root,
                        dirs_exist_ok=True,
                        ignore=self._copy_ignore,
                    )

                    result = (
                        self.executor.execute(
                            witness=witness,
                            copy_root=copy_root,
                            run_index=index,
                        )
                    )
                finally:
                    # Always widen, even if execute() raised -- the run
                    # root is retained for post-mortem evidence (see the
                    # comment in the except block below), and post-mortem
                    # evidence the host user can't read is useless.
                    self._widen_permissions(
                        run_root
                    )

                required = (
                    "trace_path",
                    "control_path",
                    "control_trace_path",
                    "environment_path",
                    "control_sha256",
                    "environment_hash",
                )

                missing = [
                    key
                    for key in required
                    if key not in result
                ]

                if missing:
                    raise ValueError(
                        "replay executor did not return "
                        "required artifacts: "
                        f"{missing}"
                    )

                trace_path = Path(
                    str(result["trace_path"])
                ).resolve()

                control_path = Path(
                    str(result["control_path"])
                ).resolve()

                control_trace_path = Path(
                    str(
                        result[
                            "control_trace_path"
                        ]
                    )
                ).resolve()

                environment_path = Path(
                    str(
                        result[
                            "environment_path"
                        ]
                    )
                ).resolve()

                artifact_dir = Path(
                    str(
                        result.get(
                            "artifact_dir",
                            trace_path.parent,
                        )
                    )
                ).resolve()

                copy_root_resolved = (
                    copy_root.resolve()
                )

                for path in (
                    trace_path,
                    control_path,
                    control_trace_path,
                    environment_path,
                ):
                    if (
                        not path.is_file()
                        or not path.is_relative_to(
                            copy_root_resolved
                        )
                    ):
                        raise ValueError(
                            "replay artifact is missing "
                            "or outside fresh copy: "
                            f"{path}"
                        )

                trace_obj = json.loads(
                    trace_path.read_text(
                        encoding="utf-8"
                    )
                )

                structured = parse_trace(
                    trace_obj,
                    cheatcode_catalog=(
                        self.cheatcode_catalog
                    ),
                )

                enforce_time_block_limits(
                    structured,
                    max_time_advance_s=(
                        witness.max_time_advance_s
                    ),
                    max_block_advance=(
                        witness.max_block_advance
                    ),
                )

                enforce_cheatcode_policy(
                    structured,
                    witness_class=(
                        witness.witness_class
                    ),
                    policy=(
                        self.cheatcode_policy
                    ),
                    fork_block=(
                        witness.fork_block
                    ),
                )

                replay_runs.append(
                    ReplayRun(
                        index=index,
                        passed=bool(
                            result.get("passed")
                        ),
                        artifact_dir=artifact_dir,
                        trace_path=trace_path,
                        control_path=control_path,
                        control_trace_path=(
                            control_trace_path
                        ),
                        environment_path=(
                            environment_path
                        ),
                        control_sha256=str(
                            result[
                                "control_sha256"
                            ]
                        ),
                        environment_hash=str(
                            result[
                                "environment_hash"
                            ]
                        ),
                        structured=structured,
                    )
                )

        except Exception:
            # Retain run roots for post-mortem evidence.
            # The caller decides whether to clean them.
            raise

        if not all(
            run.passed
            for run in replay_runs
        ):
            raise ValueError(
                "not all replay runs passed"
            )

        environment_hashes = {
            run.environment_hash
            for run in replay_runs
        }

        if len(environment_hashes) != 1:
            raise ValueError(
                "NONDETERMINISTIC_ENV"
            )

        observed_environment_hash = next(
            iter(environment_hashes)
        )

        if (
            observed_environment_hash
            != witness.env_hash
        ):
            raise ValueError(
                "ENV_DECLARATION_MISMATCH"
            )

        records = [
            run.structured
            .observed_records_sha256()
            for run in replay_runs
        ]

        if len(set(records)) != 1:
            raise ValueError(
                "NONDETERMINISTIC_TRACE"
            )

        controls = {
            run.control_sha256
            for run in replay_runs
        }

        if len(controls) != 1:
            raise ValueError(
                "CONTROL_NONDETERMINISTIC"
            )

        trace_policy_sha = _canonical_hash(
            {
                "catalog": (
                    self.cheatcode_catalog
                ),
                "policy": (
                    self.cheatcode_policy
                ),
            }
        )

        records_sha = _canonical_hash(
            records
        )

        return ReplayCollection(
            witness_hash=witness_hash(
                witness
            ),
            root=root,
            runs=tuple(replay_runs),
            observed_records_sha256=(
                records_sha
            ),
            trace_policy_sha256=(
                trace_policy_sha
            ),
            control_sha256=next(
                iter(controls)
            ),
            environment_hash=(
                observed_environment_hash
            ),
        )