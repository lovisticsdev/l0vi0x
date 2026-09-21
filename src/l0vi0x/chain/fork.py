from __future__ import annotations

from dataclasses import dataclass

from l0vi0x.chain.rpc_gate import RpcGateClient


@dataclass(frozen=True, slots=True)
class Fork:
    chain_id: int
    block_number: int
    provider_label: str
    gate_url: str


class GateForkClient:
    def __init__(self, client: RpcGateClient, *, provider_label: str) -> None:
        self.client = client
        self.provider_label = provider_label

    def pinned_fork(self, *, expected_chain_id: int, expected_block: int) -> Fork:
        chain = self.client.call("eth_chainId")
        block = self.client.call("eth_blockNumber")
        chain_id = int(chain.get("result", "0x0"), 16)
        block_no = int(block.get("result", "0x0"), 16)
        if chain_id != expected_chain_id:
            raise ValueError(f"chain id mismatch: {chain_id} != {expected_chain_id}")
        if block_no != expected_block:
            raise ValueError(f"block mismatch: {block_no} != {expected_block}")
        return Fork(chain_id, block_no, self.provider_label, self.client.gate_url)
