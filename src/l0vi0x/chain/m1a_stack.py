"""Host-side fork stack used by ``make m1a-acceptance``.

    fixture upstream Anvil  --(forked at FORK_BLOCK)-->  gate-side Anvil  <--  /agent  <--  forge
                                                                              ^
                                        docker/rpc_gate.py (the real gate) ---+--- /upstream (host only)

The stack is started and torn down inside the acceptance run, so no Docker, no external RPC provider
and no manually exported ``GATE_URL`` are needed. The real ``docker/rpc_gate.py`` process is used, so
the authentication, allowlist and logging that the acceptance exercises are the production ones.

The fixture upstream chain is deterministic:

* block 1: ``M1aTarget`` deployed by Anvil dev account 0 -> ``TARGET_ADDRESS`` (CREATE, nonce 0)
* block 2: ``fund(ATTACKER, FIXTURE_CREDIT)``
* block 3: empty block with the explicit timestamp ``UPSTREAM_GENESIS_TIMESTAMP + 100``  (the pinned fork block)
* block 4: empty block, so the pin is strictly behind the upstream head
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import time
from typing import Any
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from eth_hash.auto import keccak

from l0vi0x.chain.fork import GateForkClient
from l0vi0x.chain.m1a_fixtures import FIXTURE_ATTACKER, FIXTURE_CHAIN_ID
from l0vi0x.chain.rpc_gate import RpcGateClient
from l0vi0x.tools.anvil import AnvilController, AnvilProcess


UPSTREAM_GENESIS_TIMESTAMP = 1_700_000_000
FORK_BLOCK = 3
UPSTREAM_HEAD = 4
TARGET_ADDRESS = "0x5fbdb2315678afecb367f032d93f642f64180aa3"
FIXTURE_CREDIT = 3


class StackError(RuntimeError):
    pass


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def rpc_call(url: str, method: str, params: list[Any] | None = None, *, headers: dict[str, str] | None = None, timeout: float = 10.0) -> tuple[int, dict[str, Any]]:
    """POST one JSON-RPC request. HTTP 4xx/5xx bodies are returned rather than raised."""
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params or []}).encode()
    request = Request(url, data=body, headers={"Content-Type": "application/json", **(headers or {})}, method="POST")
    try:
        with urlopen(request, timeout=timeout) as response:
            return response.status, json.loads(response.read().decode())
    except HTTPError as exc:
        try:
            return exc.code, json.loads(exc.read().decode())
        except Exception:
            return exc.code, {}


def _result(url: str, method: str, params: list[Any] | None = None) -> Any:
    status, body = rpc_call(url, method, params)
    if status != 200 or "error" in body:
        raise StackError(f"{method} failed: HTTP {status} {body.get('error')}")
    return body["result"]


def _word_address(address: str) -> str:
    return address.removeprefix("0x").rjust(64, "0")


def _word_int(value: int) -> str:
    return hex(value)[2:].rjust(64, "0")


class M1aStack:
    def __init__(self, *, work_dir: str | Path, repo_root: str | Path, target_creation_code_hex: str, anvil_bin: str = "anvil") -> None:
        self.work_dir = Path(work_dir)
        self.repo_root = Path(repo_root)
        self.target_creation_code_hex = target_creation_code_hex
        self.anvil_bin = anvil_bin
        self.agent_token = secrets.token_urlsafe(24)
        self.upstream_token = secrets.token_urlsafe(24)
        self.gate_log_path = self.work_dir / "rpc-gate.jsonl"
        self.gate_port = 0
        self._upstream: AnvilProcess | None = None
        self._gate_side: AnvilProcess | None = None
        self._gate: subprocess.Popen[bytes] | None = None
        self._gate_stderr: Any = None

    # ---- lifecycle -------------------------------------------------------------------------
    def __enter__(self) -> "M1aStack":
        try:
            self._start()
        except BaseException:
            self._stop()
            raise
        return self

    def __exit__(self, *exc: object) -> None:
        self._stop()

    @property
    def gate_base_url(self) -> str:
        return f"http://127.0.0.1:{self.gate_port}"

    @property
    def gate_url(self) -> str:
        """Agent endpoint with the credential as URL userinfo: the only way Foundry can authenticate."""
        return f"http://agent:{self.agent_token}@127.0.0.1:{self.gate_port}/agent"

    def _start(self) -> None:
        self.work_dir.mkdir(parents=True, exist_ok=True)
        controller = AnvilController(self.anvil_bin)
        self._upstream = controller.start(
            fork_url=None, fork_block=None, chain_id=FIXTURE_CHAIN_ID, port=_free_port(),
            extra_args=("--silent", "--timestamp", str(UPSTREAM_GENESIS_TIMESTAMP)),
        )
        self._build_upstream_fixture(self._upstream.rpc_url)
        self._gate_side = controller.start(
            fork_url=self._upstream.rpc_url, fork_block=FORK_BLOCK, chain_id=FIXTURE_CHAIN_ID, port=_free_port(),
            extra_args=("--silent",),
        )
        self._start_gate(self._gate_side.rpc_url, self._upstream.rpc_url)
        pinned = GateForkClient(RpcGateClient(self.gate_base_url, token=self.agent_token), provider_label="m1a-fixture-upstream")
        pinned.pinned_fork(expected_chain_id=FIXTURE_CHAIN_ID, expected_block=FORK_BLOCK)

    def _stop(self) -> None:
        if self._gate is not None and self._gate.poll() is None:
            self._gate.terminate()
            try:
                self._gate.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._gate.kill()
                self._gate.wait(timeout=5)
        if self._gate_stderr is not None:
            self._gate_stderr.close()
        for node in (self._gate_side, self._upstream):
            if node is not None:
                node.stop()
        self._gate = self._gate_side = self._upstream = None

    # ---- fixture upstream ------------------------------------------------------------------
    def _send(self, url: str, tx: dict[str, Any]) -> dict[str, Any]:
        tx_hash = _result(url, "eth_sendTransaction", [tx])
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            receipt = _result(url, "eth_getTransactionReceipt", [tx_hash])
            if receipt:
                if receipt.get("status") != "0x1":
                    raise StackError("fixture upstream transaction reverted")
                return receipt
            time.sleep(0.05)
        raise StackError("fixture upstream transaction was not mined")

    def _build_upstream_fixture(self, url: str) -> None:
        account = _result(url, "eth_accounts")[0]
        deployed = self._send(url, {"from": account, "data": self.target_creation_code_hex, "gas": hex(1_000_000)})
        if str(deployed.get("contractAddress", "")).lower() != TARGET_ADDRESS:
            raise StackError(f"fixture target deployed at {deployed.get('contractAddress')}, expected {TARGET_ADDRESS}")
        selector = keccak(b"fund(address,uint256)")[:4].hex()
        calldata = "0x" + selector + _word_address(FIXTURE_ATTACKER) + _word_int(FIXTURE_CREDIT)
        self._send(url, {"from": account, "to": TARGET_ADDRESS, "data": calldata, "gas": hex(200_000)})
        # Explicit timestamps make the pinned block header reproducible across acceptance runs.
        _result(url, "evm_mine", [UPSTREAM_GENESIS_TIMESTAMP + 100])
        _result(url, "evm_mine", [UPSTREAM_GENESIS_TIMESTAMP + 200])
        head = int(_result(url, "eth_blockNumber"), 16)
        if head != UPSTREAM_HEAD:
            raise StackError(f"fixture upstream head is {head}, expected {UPSTREAM_HEAD}")
        pinned = _result(url, "eth_getBlockByNumber", [hex(FORK_BLOCK), False])
        if int(pinned["timestamp"], 16) != UPSTREAM_GENESIS_TIMESTAMP + 100:
            raise StackError("pinned fork block does not carry the explicit fixture timestamp")
        selector = keccak(b"snapshot(address)")[:4].hex()
        credit = _result(url, "eth_call", [{"to": TARGET_ADDRESS, "data": "0x" + selector + _word_address(FIXTURE_ATTACKER)}, hex(FORK_BLOCK)])
        if int(credit, 16) != FIXTURE_CREDIT:
            raise StackError("fixture credit is not visible at the pinned block")

    # ---- gate ------------------------------------------------------------------------------
    def _start_gate(self, agent_backend_url: str, upstream_url: str) -> None:
        self.gate_port = _free_port()
        env = dict(os.environ)
        env.update({
            "GATE_AGENT_TOKEN": self.agent_token,
            "GATE_UPSTREAM_TOKEN": self.upstream_token,
            "ANVIL_RPC_URL": agent_backend_url,
            "UPSTREAM_RPC_URL": upstream_url,
            "AUDIT_ID": "M1A",
            "RPC_GATE_LOG": str(self.gate_log_path),
            "RPC_GATE_PORT": str(self.gate_port),
            "RPC_GATE_HOST": "127.0.0.1",
            "START_ANVIL": "0",
        })
        self.gate_log_path.unlink(missing_ok=True)
        self._gate_stderr = (self.work_dir / "rpc-gate.stderr").open("wb")
        self._gate = subprocess.Popen(
            [sys.executable, str(self.repo_root / "docker" / "rpc_gate.py")],
            env=env, stdout=subprocess.DEVNULL, stderr=self._gate_stderr, shell=False,
        )
        auth = {"Authorization": f"Bearer {self.agent_token}"}
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if self._gate.poll() is not None:
                raise StackError("RPC gate exited during startup: " + (self.work_dir / "rpc-gate.stderr").read_text(errors="replace")[-800:])
            try:
                status, _ = rpc_call(self.gate_base_url + "/agent", "eth_chainId", headers=auth, timeout=1.0)
                if status == 200:
                    return
            except OSError:
                pass
            time.sleep(0.05)
        raise StackError("RPC gate did not become ready")

    # ---- queries used by the acceptance ---------------------------------------------------
    def fork_block_env(self) -> tuple[int, int]:
        """(timestamp, number) of the pinned fork block, read through the authenticated agent gate."""
        reply = RpcGateClient(self.gate_base_url, token=self.agent_token).call("eth_getBlockByNumber", [hex(FORK_BLOCK), False])
        block = reply.get("result")
        if not isinstance(block, dict):
            raise StackError(f"cannot read pinned fork block through the gate: {reply.get('error')}")
        timestamp, number = int(block["timestamp"], 16), int(block["number"], 16)
        if number != FORK_BLOCK:
            raise StackError(f"gate returned block {number}, expected {FORK_BLOCK}")
        return timestamp, number

    def probe_gate(self) -> list[str]:
        """Live check of 'denied agent/upstream RPC methods are refused and logged'."""
        agent, upstream = self.gate_base_url + "/agent", self.gate_base_url + "/upstream"
        bearer = lambda token: {"Authorization": f"Bearer {token}"}  # noqa: E731
        secret_marker = "M1A-PROBE-SECRET"
        # (endpoint, url, method, params, headers, expected HTTP status)
        probes: list[tuple[str, str, str, list[Any], dict[str, str], int]] = [
            ("agent", agent, "eth_blockNumber", [], bearer(self.agent_token), 200),
            ("agent", agent, "eth_sendRawTransaction", [{"privateKey": secret_marker}], bearer(self.agent_token), 403),
            ("agent", agent, "eth_sendTransaction", [], bearer(self.agent_token), 403),
            ("agent", agent, "anvil_setBalance", [], bearer(self.agent_token), 403),
            ("agent", agent, "evm_mine", [], bearer(self.agent_token), 403),
            ("agent", agent, "eth_blockNumber", [], bearer("wrong-token"), 401),
            ("agent", agent, "eth_blockNumber", [], bearer(self.upstream_token), 401),
            ("upstream", upstream, "eth_blockNumber", [], bearer(self.upstream_token), 200),
            ("upstream", upstream, "evm_mine", [], bearer(self.upstream_token), 403),
            ("upstream", upstream, "anvil_setBalance", [], bearer(self.upstream_token), 403),
            ("upstream", upstream, "eth_sendRawTransaction", [], bearer(self.upstream_token), 403),
            ("upstream", upstream, "eth_blockNumber", [], bearer(self.agent_token), 401),
        ]
        report: list[str] = []
        for endpoint, url, method, params, headers, expected in probes:
            status, body = rpc_call(url, method, params, headers=headers)
            if status != expected:
                raise StackError(f"gate {endpoint} {method}: HTTP {status}, expected {expected}")
            if expected == 200 and "result" not in body:
                raise StackError(f"gate {endpoint} {method}: allowed call returned no result")
            report.append(f"{endpoint}:{method} -> {status}")
        entries = [json.loads(line) for line in self.gate_log_path.read_text(encoding="utf-8").splitlines() if line.strip()]
        for endpoint, _url, method, _params, _headers, expected in probes:
            hits = [e for e in entries if e["endpoint"] == endpoint and e["method"] == method and e["status"] == expected]
            if not hits or any(bool(e["allowed"]) != (expected == 200) for e in hits):
                raise StackError(f"gate log is missing the {expected} decision for {endpoint}:{method}")
        raw_log = self.gate_log_path.read_text(encoding="utf-8")
        if secret_marker in raw_log or self.agent_token in raw_log or self.upstream_token in raw_log:
            raise StackError("gate log contains an unredacted secret")
        if "<redacted>" not in raw_log:
            raise StackError("gate log did not redact the secret-looking parameter")
        return report
