from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import secrets
from threading import Lock
from typing import Any
from urllib.request import Request, urlopen

import yaml


_WRITE_OR_ADMIN_PREFIXES = (
    "anvil_", "hardhat_", "evm_set", "evm_mine", "evm_increasetime", "evm_setnextblocktimestamp",
    "eth_sendrawtransaction", "eth_sendtransaction", "eth_sendunsignedtransaction", "eth_sign",
    "personal_", "debug_set", "debug_tracecall",
)


@dataclass(frozen=True, slots=True)
class GateDecision:
    allowed: bool
    status: int
    error_code: int | None
    reason: str | None = None


class RpcGate:
    """Transport-neutral fail-closed RPC policy and audit logger."""

    def __init__(
        self,
        policy_path: str | Path,
        *,
        audit_id: str,
        log_dir: str | Path,
        agent_token: str | None = None,
        upstream_token: str | None = None,
    ) -> None:
        self.policy_path = Path(policy_path)
        self.audit_id = audit_id
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.agent_token = agent_token or secrets.token_urlsafe(24)
        self.upstream_token = upstream_token or secrets.token_urlsafe(24)
        self._lock = Lock()
        self.policy = yaml.safe_load(self.policy_path.read_text(encoding="utf-8")) or {}

    def decision(self, endpoint: str, method: str, token: str | None) -> GateDecision:
        if endpoint not in {"agent", "upstream", "cross_check"}:
            return GateDecision(False, 404, -32601, "unknown endpoint")
        expected = {
            "agent": self.agent_token,
            "upstream": self.upstream_token,
            "cross_check": self.upstream_token,
        }[endpoint]
        if not token or not secrets.compare_digest(token, expected):
            return GateDecision(False, 401, -32001, "authentication failed")

        endpoint_cfg = _endpoint_config(self.policy, endpoint)
        allow = set(endpoint_cfg.get("allow", endpoint_cfg.get("allow_methods", [])))
        denied_prefixes = {str(p).lower() for p in endpoint_cfg.get("deny_prefixes", [])}
        method_l = method.lower()
        if any(method_l.startswith(prefix) for prefix in denied_prefixes):
            return GateDecision(False, 403, -32601, "RPC method denied")
        if endpoint in {"upstream", "cross_check"} and any(method_l.startswith(prefix) for prefix in _WRITE_OR_ADMIN_PREFIXES):
            return GateDecision(False, 403, -32601, "RPC method denied")
        if method not in allow:
            return GateDecision(False, 403, -32601, "RPC method denied")
        return GateDecision(True, 200, None)

    def record(
        self,
        *,
        endpoint: str,
        method: str,
        result_code: int,
        latency_ms: int,
        params: Any,
        allowed: bool,
    ) -> Path:
        payload = {
            "endpoint": endpoint,
            "method": method,
            "audit_id": self.audit_id,
            "result_code": result_code,
            "latency_ms": latency_ms,
            "params": _redact_params(params),
            "allowed": allowed,
        }
        digest = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()[:16]
        path = self.log_dir / f"rpc-{digest}.jsonl"
        with self._lock:
            with path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n")
        return path

    def forward(
        self,
        *,
        endpoint: str,
        method: str,
        params: Any = None,
        url: str,
        token: str,
        timeout_s: float = 30.0,
    ) -> dict[str, Any]:
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
                body = response.read().decode("utf-8")
                status = response.status
            out = json.loads(body)
        except Exception as exc:
            status = 502
            out = {"jsonrpc": "2.0", "error": {"code": -32002, "message": str(exc)}, "id": 1}
        latency = int((time.monotonic() - started) * 1000)
        self.record(endpoint=endpoint, method=method, result_code=status, latency_ms=latency, params=params, allowed=True)
        return out


def _endpoint_config(policy: dict[str, Any], endpoint: str) -> dict[str, Any]:
    endpoints = policy.get("endpoints")
    if isinstance(endpoints, dict) and isinstance(endpoints.get(endpoint), dict):
        return endpoints[endpoint]
    legacy = policy.get(endpoint)
    return legacy if isinstance(legacy, dict) else {}


def _redact_params(params: Any) -> Any:
    if isinstance(params, dict):
        redacted = {}
        for k, v in params.items():
            lk = str(k).lower()
            if any(secret in lk for secret in ("key", "token", "secret", "password", "mnemonic", "credential", "private")):
                redacted[k] = "<redacted>"
            else:
                redacted[k] = _redact_params(v)
        return redacted
    if isinstance(params, list):
        return [_redact_params(v) for v in params]
    if isinstance(params, str):
        # Strings themselves may be raw URLs or credentials embedded in query/userinfo.
        from urllib.parse import urlsplit, urlunsplit
        parts = urlsplit(params)
        if parts.scheme and parts.netloc:
            host = parts.hostname or ""
            netloc = host + (f":{parts.port}" if parts.port is not None else "")
            return urlunsplit((parts.scheme, netloc, "", "", ""))
    return params


class RpcGateClient:
    def __init__(self, gate_url: str, *, token: str, timeout_s: float = 30.0) -> None:
        self.gate_url = gate_url.rstrip("/")
        self.token = token
        self.timeout_s = timeout_s

    def call(self, method: str, params: list[Any] | None = None, *, endpoint: str = "agent") -> dict[str, Any]:
        request = Request(
            self.gate_url + f"/{endpoint}",
            data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params or []}).encode(),
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {self.token}"},
            method="POST",
        )
        try:
            with urlopen(request, timeout=self.timeout_s) as response:
                return json.loads(response.read().decode("utf-8"))
        except Exception as exc:
            return {"jsonrpc": "2.0", "id": 1, "error": {"code": -32002, "message": str(exc)}}
