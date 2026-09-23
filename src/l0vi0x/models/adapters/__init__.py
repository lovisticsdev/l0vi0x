from __future__ import annotations

from typing import Any

from l0vi0x.models.adapters.base import Adapter
from l0vi0x.models.adapters.fake import FakeAdapter
from l0vi0x.models.adapters.openai_compat import OpenAICompatAdapter

_KINDS = {"fake": FakeAdapter, "openai_compat": OpenAICompatAdapter}


def build_adapter(config: dict[str, Any]) -> Adapter:
    """Construct an adapter from a stack config entry by `kind` alone.

    This is the M2.1 stop condition made concrete: swapping `fake` for
    `openai_compat` is a config change (`{"kind": "openai_compat", ...}`
    vs `{"kind": "fake", ...}`), never a call-site change -- callers only
    ever hold an `Adapter`.
    """
    kind = config.get("kind")
    cls = _KINDS.get(kind)
    if cls is None:
        raise ValueError(f"unknown adapter kind: {kind!r} (known: {sorted(_KINDS)})")
    kwargs = {k: v for k, v in config.items() if k != "kind"}
    return cls(**kwargs)


__all__ = ["Adapter", "FakeAdapter", "OpenAICompatAdapter", "build_adapter"]
