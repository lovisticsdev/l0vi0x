from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import secrets
import subprocess
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.request import Request, urlopen


POLICY_PATH = Path(__file__).resolve().parent.parent / "config/policy/rpc_allowlist.yaml"

_WRITE_OR_ADMIN_PREFIXES = (
    "anvil_", "hardhat_", "evm_set", "evm_mine", "evm_increasetime", "evm_setnextblocktimestamp",
    "eth_sendrawtransaction", "eth_sendtransaction", "eth_sendunsignedtransaction", "eth_sign",
    "personal_", "debug_set", "debug_tracecall",
)


def load_policy() -> dict:
    import yaml
    data = yaml.safe_load(POLICY_PATH.read_text(encoding="utf-8"))
    return data or {}


def _endpoint_config(policy: dict, endpoint: str) -> dict:
    endpoints = policy.get("endpoints")
    if isinstance(endpoints, dict) and isinstance(endpoints.get(endpoint), dict):
        return endpoints[endpoint]
    legacy = policy.get(endpoint)
    return legacy if isinstance(legacy, dict) else {}


def redact_params(params):
    if isinstance(params, dict):
        out = {}
        for k, v in params.items():
            lk = str(k).lower()
            out[k] = "<redacted>" if any(x in lk for x in ("key", "token", "secret", "password", "mnemonic", "credential", "private")) else redact_params(v)
        return out
    if isinstance(params, list):
        return [redact_params(v) for v in params]
    if isinstance(params, str) and len(params) > 256:
        return params[:256] + "…<truncated>"
    if isinstance(params, str) and "://" in params:
        from urllib.parse import urlsplit, urlunsplit
        parts = urlsplit(params)
        if parts.scheme and parts.netloc:
            host = parts.hostname or ""
            netloc = host + (f":{parts.port}" if parts.port is not None else "")
            return urlunsplit((parts.scheme, netloc, "", "", ""))
    return params


class GateState:
    def __init__(self) -> None:
        self.policy = load_policy()
        self.agent_token = os.environ.get("GATE_AGENT_TOKEN", "")
        self.upstream_token = os.environ.get("GATE_UPSTREAM_TOKEN", "")
        if not self.agent_token or not self.upstream_token:
            raise RuntimeError("GATE_AGENT_TOKEN and GATE_UPSTREAM_TOKEN are required")
        self.anvil_url = os.environ.get("ANVIL_RPC_URL", "http://127.0.0.1:8546")
        self.upstream_url = os.environ.get("UPSTREAM_RPC_URL", "")
        self.cross_check_url = os.environ.get("CROSS_CHECK_RPC_URL", self.upstream_url)
        self.audit_id = os.environ.get("AUDIT_ID", "unknown")
        self.log_path = Path(os.environ.get("RPC_GATE_LOG", "/var/log/l0vi0x/rpc-gate.jsonl"))
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

    def authorize(self, endpoint: str, method: str, authorization: str | None) -> tuple[bool, int, str]:
        expected = {"agent": self.agent_token, "upstream": self.upstream_token, "cross_check": self.upstream_token}.get(endpoint)
        if expected is None:
            return False, 404, "not found"
        supplied = (authorization or "")
        if supplied.startswith("Bearer "):
            supplied = supplied[7:]
        elif supplied.startswith("Basic "):
            try:
                decoded = base64.b64decode(supplied[6:], validate=True).decode("utf-8")
                _user, supplied = decoded.split(":", 1)
            except Exception:
                supplied = ""
        if not supplied or not secrets.compare_digest(supplied, expected):
            return False, 401, "authentication failed"
        cfg = _endpoint_config(self.policy, endpoint)
        allow = set(cfg.get("allow", cfg.get("allow_methods", [])))
        deny_prefixes = {str(p).lower() for p in cfg.get("deny_prefixes", [])}
        method_l = method.lower()
        if any(method_l.startswith(prefix) for prefix in deny_prefixes):
            return False, 403, "RPC method denied"
        if endpoint in {"upstream", "cross_check"} and any(method_l.startswith(prefix) for prefix in _WRITE_OR_ADMIN_PREFIXES):
            return False, 403, "RPC method denied"
        if method not in allow:
            return False, 403, "RPC method denied"
        return True, 200, "ok"

    def log(self, endpoint: str, method: str, code: int, allowed: bool, params, latency_ms: int) -> None:
        payload = {"audit_id": self.audit_id, "endpoint": endpoint, "method": method, "status": code, "allowed": allowed, "params": redact_params(params), "latency_ms": latency_ms}
        with self.log_path.open("a", encoding="utf-8") as fh:
            json.dump(payload, fh, sort_keys=True)
            fh.write("\n")

    def forward(self, endpoint: str, payload: dict) -> tuple[int, dict, int]:
        target = {"agent": self.anvil_url, "upstream": self.upstream_url, "cross_check": self.cross_check_url}.get(endpoint, "")
        if not target:
            return 502, {"jsonrpc": "2.0", "id": payload.get("id"), "error": {"code": -32002, "message": "endpoint URL unavailable"}}, 0
        req = Request(target, data=json.dumps(payload).encode(), headers={"Content-Type": "application/json"}, method="POST")
        started = time.monotonic()
        try:
            with urlopen(req, timeout=30) as response:
                body = response.read().decode("utf-8")
                status = response.status
            out = json.loads(body)
        except Exception as exc:
            status = 502
            out = {"jsonrpc": "2.0", "id": payload.get("id"), "error": {"code": -32002, "message": str(exc)}}
        return status, out, int((time.monotonic() - started) * 1000)


STATE = None
_ANVIL_PROC = None


def start_anvil_if_requested() -> None:
    global _ANVIL_PROC
    if os.environ.get("START_ANVIL", "0") != "1":
        return
    args = [os.environ.get("ANVIL_BIN", "anvil"), "--host", "127.0.0.1", "--port", os.environ.get("ANVIL_PORT", "8546"), "--chain-id", os.environ.get("ANVIL_CHAIN_ID", "31337")]
    fork_url = os.environ.get("UPSTREAM_RPC_URL")
    fork_block = os.environ.get("FORK_BLOCK")
    if fork_url:
        args += ["--fork-url", fork_url]
    if fork_block:
        args += ["--fork-block-number", fork_block]
    _ANVIL_PROC = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True, shell=False)


class Handler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:  # noqa: N802
        endpoint = "agent" if self.path == "/agent" else "upstream" if self.path == "/upstream" else "cross_check" if self.path == "/cross_check" else None
        if endpoint is None:
            self.send_error(404, "not found")
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            payload = json.loads(self.rfile.read(length))
            if not isinstance(payload, dict):
                raise ValueError("JSON-RPC payload must be an object")
            method = str(payload.get("method", ""))
        except Exception:
            self._write_json(400, {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "invalid JSON"}})
            return
        ok, status, reason = STATE.authorize(endpoint, method, self.headers.get("Authorization"))
        if not ok:
            STATE.log(endpoint, method, status, False, payload.get("params"), 0)
            self._write_json(status, {"jsonrpc": "2.0", "id": payload.get("id"), "error": {"code": -32601 if status == 403 else -32001, "message": reason}})
            return
        status, response, latency = STATE.forward(endpoint, payload)
        STATE.log(endpoint, method, status, status < 400, payload.get("params"), latency)
        self._write_json(status, response)

    def _write_json(self, status: int, payload: dict) -> None:
        data = json.dumps(payload, sort_keys=True).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, fmt: str, *args: object) -> None:
        return


if __name__ == "__main__":
    start_anvil_if_requested()
    STATE = GateState()
    port = int(os.environ.get("RPC_GATE_PORT", "8545"))
    try:
        ThreadingHTTPServer((os.environ.get("RPC_GATE_HOST", "0.0.0.0"), port), Handler).serve_forever()
    finally:
        if _ANVIL_PROC is not None and _ANVIL_PROC.poll() is None:
            _ANVIL_PROC.terminate()
