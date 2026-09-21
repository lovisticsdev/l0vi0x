from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import secrets
from threading import Lock
from typing import Any, Callable, Mapping
from urllib.request import Request, urlopen

import yaml


@dataclass(frozen=True, slots=True)
class GateDecision:
    allowed: bool
    status: int
    error_code: int | None
    reason: str | None = None


class RpcGate:
    """Allowlist/authentication/recording policy for the two gate endpoints.

    The class is transport-neutral so tests can exercise fail-closed behavior without Docker.
    The HTTP server in docker/rpc_gate.py delegates to the same rules.
    """

    def __init__(self, policy_path: str | Path, *, audit_id: str, log_dir: str | Path, agent_token: str | None = None, upstream_token: str | None = None) -> None:
        self.policy_path = Path(policy_path)
        self.audit_id = audit_id
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.agent_token = agent_token or secrets.token_urlsafe(24)
        self.upstream_token = upstream_token or secrets.token_urlsafe(24)
        self._lock = Lock()
        self.policy = yaml.safe_load(self.policy_path.read_text(encoding="utf-8"))

    def decision(self, endpoint: str, method: str, token: str | None) -> GateDecision:
        if endpoint not in {"agent", "upstream"}:
            return GateDecision(False, 404, -32601, "unknown endpoint")
        expected = self.agent_token if endpoint == "agent" else self.upstream_token
        if not token or not secrets.compare_digest(token, expected):
            return GateDecision(False, 401, -32001, "authentication failed")
        allowed = set(self.policy.get(endpoint, {}).get("allow_methods", []))
        if method not in allowed:
            return GateDecision(False, 403, -32601, "RPC method denied")
        if endpoint == "upstream" and method.lower().startswith(("evm_", "anvil_", "hardhat_", "debug_")):
            return GateDecision(False, 403, -32601, "upstream write/admin method denied")
        return GateDecision(True, 200, None)

    def record(self, *, endpoint: str, method: str, result_code: int, latency_ms: int, params: Any, allowed: bool) -> Path:
        safe_params = _redact_params(params)
        payload = {
            "endpoint": endpoint,
            "method": method,
            "audit_id": self.audit_id,
            "result_code": result_code,
            "latency_ms": latency_ms,
            "params": safe_params,
            "allowed": allowed,
        }
        digest = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()[:16]
        path = self.log_dir / f"rpc-{digest}.jsonl"
        with self._lock:
            with path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n")
        return path

    def forward(self, *, endpoint: str, method: str, params: Any = None, url: str, token: str, timeout_s: float = 30.0) -> dict[str, Any]:
        import time

        decision = self.decision(endpoint, method, token)
        if not decision.allowed:
            self.record(endpoint=endpoint, method=method, result_code=decision.status, latency_ms=0, params=params, allowed=False)
            return {"jsonrpc": "2.0", "error": {"code": decision.error_code, "message": decision.reason}, "id": 1}
        payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params or []}).encode()
        request = Request(url, data=payload, headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"}, method="POST")
        started = time.monotonic()
        try:
            with urlopen(request, timeout=timeout_s) as response:
                body = response.read().decode()
                status = response.status
            out = json.loads(body)
        except Exception as exc:
            status = 502
            out = {"jsonrpc": "2.0", "error": {"code": -32002, "message": str(exc)}, "id": 1}
        latency = int((time.monotonic() - started) * 1000)
        self.record(endpoint=endpoint, method=method, result_code=status, latency_ms=latency, params=params, allowed=True)
        return out


def _redact_params(params: Any) -> Any:
    if isinstance(params, dict):
        redacted = {}
        for k, v in params.items():
            lk = str(k).lower()
            redacted[k] = "<redacted>" if any(secret in lk for secret in ("key", "token", "secret", "password", "mnemonic")) else _redact_params(v)
        return redacted
    if isinstance(params, list):
        return [_redact_params(v) for v in params]
    return params


class RpcGateClient:
    def __init__(self, gate_url: str, *, token: str, timeout_s: float = 30.0) -> None:
        self.gate_url = gate_url.rstrip("/")
        self.token = token
        self.timeout_s = timeout_s

    def call(self, method: str, params: list[Any] | None = None) -> dict[str, Any]:
        request = Request(
            self.gate_url + "/agent",
            data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params or []}).encode(),
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {self.token}"},
            method="POST",
        )
        with urlopen(request, timeout=self.timeout_s) as response:
            return json.loads(response.read().decode())
