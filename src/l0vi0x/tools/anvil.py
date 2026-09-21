from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import signal
import time
from typing import Sequence
from urllib.request import Request, urlopen

from l0vi0x.tools.runner import run


@dataclass(slots=True)
class AnvilProcess:
    process: object
    rpc_url: str
    chain_id: int
    block_number: int | None = None

    def stop(self) -> None:
        p=self.process
        if p.poll() is None:
            p.send_signal(signal.SIGTERM)
            try: p.wait(timeout=5)
            except Exception: p.kill(); p.wait(timeout=5)


class AnvilController:
    """Host/gate-side only. Sandboxed agents never receive the upstream URL."""
    def __init__(self, anvil_bin: str = "anvil") -> None:
        self.anvil_bin=anvil_bin

    def start(self, *, fork_url: str | None, fork_block: int | None, chain_id: int, port: int = 8545, extra_args: Sequence[str] = (), tool_runs_dir: str | Path | None = None) -> AnvilProcess:
        import subprocess
        argv=[self.anvil_bin,"--host","127.0.0.1","--port",str(port),"--chain-id",str(chain_id)]
        if fork_url: argv += ["--fork-url",fork_url]
        if fork_block is not None: argv += ["--fork-block-number",str(fork_block)]
        argv += list(extra_args)
        # This process is host/gate infrastructure, but creation is still argv-only.
        p=subprocess.Popen(argv,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,shell=False)
        for _ in range(100):
            if p.poll() is not None:
                out,err=p.communicate(timeout=1); raise RuntimeError(f"anvil failed: {err or out}")
            try:
                req=Request(f"http://127.0.0.1:{port}",data=json.dumps({"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}).encode(),headers={"Content-Type":"application/json"},method="POST")
                with urlopen(req,timeout=0.5): break
            except Exception:
                time.sleep(0.05)
        else:
            p.terminate(); raise RuntimeError("anvil did not become ready")
        return AnvilProcess(p,f"http://127.0.0.1:{port}",chain_id)
