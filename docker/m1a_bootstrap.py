from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import time
from urllib.request import Request, urlopen
from urllib.error import URLError

from l0vi0x.tools.forge import build as forge_build

ROOT = Path(os.environ["L0VI0X_REPO_ROOT"]).resolve()
WORK = Path(os.environ["L0VI0X_WORK_ROOT"]).resolve()
FIXTURE = ROOT / "fixtures/m1a_foundry"
UPSTREAM = os.environ["M1A_UPSTREAM_RPC_URL"]
TARGET = "0x5fbdb2315678afecb367f032d93f642f64180aa3"
ATTACKER = "0x000000000000000000000000000000000000a11ce"

def rpc(method: str, params: list[object] | None = None) -> object:
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params or []}).encode()
    req = Request(UPSTREAM, data=body, headers={"Content-Type": "application/json"}, method="POST")
    with urlopen(req, timeout=30) as response:
        payload = json.loads(response.read().decode())
    if "error" in payload:
        raise RuntimeError(f"{method}: {payload['error']}")
    return payload["result"]

def wait_for_upstream(timeout_s: float = 30) -> None:
    deadline = time.monotonic() + timeout_s
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            rpc("eth_blockNumber")
            return
        except (URLError, RuntimeError) as exc:
            last_err = exc
            time.sleep(0.25)
    raise RuntimeError(f"m1a_upstream not reachable after {timeout_s}s: {last_err}")


def word_addr(address: str) -> str:
    return address.removeprefix("0x").rjust(64, "0")

def word_int(value: int) -> str:
    return hex(value)[2:].rjust(64, "0")

def send(tx: dict[str, str]) -> dict[str, object]:
    tx_hash = str(rpc("eth_sendTransaction", [tx]))
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        receipt = rpc("eth_getTransactionReceipt", [tx_hash])
        if receipt:
            if receipt.get("status") != "0x1":
                raise RuntimeError(f"transaction reverted: {tx_hash}")
            return receipt
        time.sleep(0.05)
    raise RuntimeError(f"transaction not mined: {tx_hash}")

def main() -> int:
    wait_for_upstream()
    accounts = rpc("eth_accounts")
    if not isinstance(accounts, list) or not accounts:
        raise RuntimeError("upstream Anvil exposes no unlocked account")
    account = str(accounts[0])
    nonce = int(str(rpc("eth_getTransactionCount", [account, "latest"])), 16)
    if nonce != 0:
        code = str(rpc("eth_getCode", [TARGET, "latest"]))
        head = int(str(rpc("eth_blockNumber")), 16)
        if code not in ("0x", "") and head >= 4:
            return 0
        raise RuntimeError(f"upstream account nonce is {nonce}, expected a fresh chain")
    scratch = WORK / "m1a-upstream-build"
    if scratch.exists():
        shutil.rmtree(scratch)
    shutil.copytree(FIXTURE, scratch)
    report = forge_build(root=scratch, forge_bin="forge", tool_runs_dir=WORK / "tool_runs")
    if not report.passed:
        raise RuntimeError(report.stderr or report.stdout or "forge build failed")
    artifact = scratch / "out/M1aTarget.sol/M1aTarget.json"
    creation = json.loads(artifact.read_text())['bytecode']['object']
    accounts = rpc("eth_accounts")
    if not isinstance(accounts, list) or not accounts:
        raise RuntimeError("upstream Anvil exposes no unlocked account")
    account = str(accounts[0])
    receipt = send({"from": account, "data": creation, "gas": hex(1_000_000)})
    if str(receipt.get("contractAddress", "")).lower() != TARGET.lower():
        raise RuntimeError(f"unexpected target address: {receipt.get('contractAddress')}")
    from eth_hash.auto import keccak
    selector = keccak(b"fund(address,uint256)")[:4].hex()
    calldata = "0x" + selector + word_addr(ATTACKER) + word_int(3)
    send({"from": account, "to": TARGET, "data": calldata, "gas": hex(200_000)})
    rpc("evm_mine", [1700000100])
    rpc("evm_mine", [1700000200])
    if int(str(rpc("eth_blockNumber")), 16) != 4:
        raise RuntimeError("upstream fixture head must be block 4")
    WORK.mkdir(parents=True, exist_ok=True)
    (WORK / "m1a-upstream-ready.json").write_text(json.dumps({"target": TARGET, "fork_block": 3, "head": 4}, indent=2) + "\n")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
