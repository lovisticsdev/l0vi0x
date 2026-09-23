from __future__ import annotations

from pathlib import Path
import hashlib
import re
import shutil
import subprocess
from datetime import datetime, timezone
from typing import Any

import yaml


def actual_sha256(path: str | Path) -> str:
    h = hashlib.sha256()
    with Path(path).open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def read_lock(path: str | Path) -> dict[str, Any]:
    return yaml.safe_load(Path(path).read_text(encoding="utf-8"))


def discover_binary(name: str, binary: str) -> Path | None:
    found = shutil.which(binary)
    return Path(found).resolve() if found else None


def command_text(binary: str, args: list[str], *, label: str) -> str:
    proc = subprocess.run([binary, *args], capture_output=True, text=True, check=False, shell=False, timeout=30)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or proc.stdout.strip() or f"{label} failed")
    return (proc.stdout + "\n" + proc.stderr).strip()


def _uv_tool_package_version(binary: str, package: str) -> str:
    """Read the distribution version from the interpreter backing a uv tool executable."""
    executable = Path(binary).resolve()
    try:
        first_line = executable.read_text(encoding="utf-8", errors="ignore").splitlines()[0]
    except (OSError, UnicodeDecodeError, IndexError):
        first_line = ""
    if first_line.startswith("#!"):
        interpreter = first_line[2:].strip().split()[0]
        if Path(interpreter).exists():
            code = "import importlib.metadata as m, sys; print(m.version(sys.argv[1]))"
            proc = subprocess.run(
                [interpreter, "-c", code, package],
                capture_output=True, text=True, check=False, shell=False, timeout=30,
            )
            if proc.returncode == 0 and proc.stdout.strip():
                return proc.stdout.strip()
            proc = subprocess.run(
                [interpreter, "-m", "pip", "show", package],
                capture_output=True, text=True, check=False, shell=False, timeout=30,
            )
            if proc.returncode == 0:
                for line in proc.stdout.splitlines():
                    if line.startswith("Version:") and line.split(":", 1)[1].strip():
                        return line.split(":", 1)[1].strip()
    # Fallback for uv installations where the launcher is not a readable script.
    uv = shutil.which("uv")
    if uv:
        proc = subprocess.run([uv, "tool", "list"], capture_output=True, text=True, check=False, shell=False, timeout=30)
        if proc.returncode == 0:
            pattern = re.compile(rf"^\s*{re.escape(package)}(?: v)?([0-9][^\s()]*)", re.MULTILINE)
            match = pattern.search(proc.stdout)
            if match:
                return match.group(1)
    raise RuntimeError(f"{package} Python distribution metadata not found")


def version_text(binary: str, *, name: str) -> tuple[str, str]:
    if name == "solc-select":
        # solc-select intentionally has no `--version` CLI option. The command is
        # usually a uv-generated launcher, so resolve its own interpreter rather
        # than looking in the project venv's package metadata.
        package_version = _uv_tool_package_version(binary, "solc-select")
        probe = command_text(binary, ["versions"], label="solc-select versions")
        return package_version, probe
    output = command_text(binary, ["--version"], label=f"{binary} --version")
    return output, output


def update_lock(config_path: str | Path, lock_path: str | Path) -> dict[str, Any]:
    config = yaml.safe_load(Path(config_path).read_text(encoding="utf-8"))
    lock: dict[str, Any] = {"version": 1, "status": "verified", "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"), "tools": {}}
    missing: list[str] = []
    for name, spec in (config.get("tools") or {}).items():
        binary = discover_binary(name, str(spec["binary"]))
        if binary is None:
            missing.append(f"{name}: {spec['binary']} not found")
            continue
        version, probe_output = version_text(str(binary), name=name)
        lock["tools"][name] = {"binary": str(binary), "version": version, "probe_output": probe_output, "sha256": actual_sha256(binary)}
    if missing:
        raise RuntimeError("cannot create complete tools.lock.yaml:\n" + "\n".join(missing))
    dest = Path(lock_path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(yaml.safe_dump(lock, sort_keys=False), encoding="utf-8")
    return lock


def verify_binary_lock(path: str | Path, *, binary_paths: dict[str, str] | None = None, required_names: list[str] | None = None, allow_extra: bool = False) -> list[str]:
    lock = read_lock(path) or {}
    problems: list[str] = []
    if lock.get("status") != "verified":
        problems.append("lock status is not verified")
    locked_tools = lock.get("tools") or {}
    if not locked_tools:
        problems.append("lock contains no tool entries")
    if required_names is None:
        sibling_config = Path(path).with_name("tools.yaml")
        if sibling_config.exists():
            config = yaml.safe_load(sibling_config.read_text(encoding="utf-8")) or {}
            required_names = list((config.get("tools") or {}).keys())
    if required_names:
        missing = sorted(set(required_names) - set(locked_tools))
        if missing:
            problems.append("missing required tools: " + ", ".join(missing))
        if not allow_extra:
            extra = sorted(set(locked_tools) - set(required_names))
            if extra:
                problems.append("unexpected locked tools: " + ", ".join(extra))
    for name, entry in locked_tools.items():
        if required_names is not None and name not in set(required_names):
            continue
        binary = (binary_paths or {}).get(name) or entry.get("binary")
        if binary and not Path(str(binary)).exists():
            portable = shutil.which(name)
            if portable:
                binary = portable
        expected_version = entry.get("version")
        expected_hash = entry.get("sha256")
        if not binary or expected_version in (None, "") or expected_hash in (None, ""):
            problems.append(f"{name}: unresolved lock entry")
            continue
        try:
            actual_version, actual_probe = version_text(str(binary), name=name)
        except Exception as exc:
            problems.append(f"{name}: version probe failed: {exc}")
            continue
        if str(expected_version).strip() != actual_version.strip():
            problems.append(f"{name}: version mismatch")
        expected_probe = entry.get("probe_output")
        if expected_probe not in (None, "") and str(expected_probe).strip() != str(actual_probe).strip():
            problems.append(f"{name}: probe output mismatch")
        if actual_sha256(binary) != expected_hash:
            problems.append(f"{name}: sha256 mismatch")
    return problems


def verify_container_binary_lock(
    lock_path: str | Path,
    *,
    image: str,
    required_names: list[str],
) -> list[str]:
    lock = read_lock(lock_path) or {}
    problems: list[str] = []

    if lock.get("status") != "verified":
        problems.append("lock status is not verified")

    image_ref = (lock.get("image") or {}).get("ref")
    if image_ref != image:
        problems.append(f"image ref mismatch: expected {image}, found {image_ref}")

    tools = lock.get("tools") or {}
    missing = sorted(set(required_names) - set(tools))
    if missing:
        problems.append("missing required tools: " + ", ".join(missing))

    for name in required_names:
        entry = tools.get(name)
        if entry is None:
            continue

        expected_version = str(entry.get("version", "")).strip()
        expected_probe = str(entry.get("probe_output", "")).strip()
        expected_hash = str(entry.get("sha256", "")).strip()

        probe = (
            f"docker run --rm --entrypoint sh {image} -lc "
            f"'for tool in {name}; do echo \"=== $tool ===\"; /usr/local/bin/$tool --version; sha256sum /usr/local/bin/$tool; done'"
        )
        proc = subprocess.run(
            probe,
            shell=True,
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode != 0:
            problems.append(f"{name}: docker probe failed: {proc.stderr.strip() or proc.stdout.strip()}")
            continue

        output = (proc.stdout + "\n" + proc.stderr).strip()
        lines = output.splitlines()
        marker = f"=== {name} ==="
        try:
            start = lines.index(marker) + 1
        except ValueError:
            start = 0
        version_lines: list[str] = []
        actual_hash = ""
        target_suffix = f"/usr/local/bin/{name}"
        for line in lines[start:]:
            stripped = line.strip()
            if not stripped:
                continue
            parts = stripped.split(None, 1)
            if len(parts) == 2 and parts[1].strip() == target_suffix:
                actual_hash = parts[0].strip()
                break
            version_lines.append(line)
        actual_version = "\n".join(version_lines).strip()
        actual_probe = actual_version

        if expected_version and actual_version and expected_version != actual_version:
            problems.append(f"{name}: version mismatch")
        if expected_probe and expected_probe not in output:
            problems.append(f"{name}: probe output mismatch")
        if expected_hash and actual_hash and expected_hash != actual_hash:
            problems.append(f"{name}: sha256 mismatch")

    return problems