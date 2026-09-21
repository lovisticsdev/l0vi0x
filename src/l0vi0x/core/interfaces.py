from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass
from typing import Any, Protocol, TYPE_CHECKING

if TYPE_CHECKING:
    from l0vi0x.core.models import Scope, ProtocolModel
    from l0vi0x.core.store import Store
    from l0vi0x.core.budget import Budget


_DRIVER_SECRET = secrets.token_bytes(32)
_ISSUER_CAP = object()


@dataclass(frozen=True, slots=True, init=False)
class DriverToken:
    """Opaque capability minted by the driver-facing issuer.

    Direct construction is intentionally disabled.  Core policy checks validate
    the issuer MAC rather than trusting caller-supplied ``authority`` fields.
    """

    driver_id: str
    human_override: bool
    _mac: str

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        raise TypeError("DriverToken is opaque; construct it through l0vi0x.driver.run")

    @classmethod
    def _mint(cls, driver_id: str, human_override: bool) -> "DriverToken":
        if not isinstance(driver_id, str) or not driver_id.strip():
            raise ValueError("driver_id must be non-empty")
        payload = f"{driver_id.strip()}|{int(human_override)}".encode()
        mac = hmac.new(_DRIVER_SECRET, payload, hashlib.sha256).hexdigest()
        obj = object.__new__(cls)
        object.__setattr__(obj, "driver_id", driver_id.strip())
        object.__setattr__(obj, "human_override", bool(human_override))
        object.__setattr__(obj, "_mac", mac)
        return obj

    def is_valid(self) -> bool:
        payload = f"{self.driver_id}|{int(self.human_override)}".encode()
        expected = hmac.new(_DRIVER_SECRET, payload, hashlib.sha256).hexdigest()
        return hmac.compare_digest(self._mac, expected)

    def __repr__(self) -> str:
        return f"DriverToken(driver_id={self.driver_id!r}, human_override={self.human_override!r})"


def _issue_driver_token(driver_id: str, *, human_override: bool = False, _issuer_cap: object = _ISSUER_CAP) -> DriverToken:
    """Issue a driver capability for the trusted driver module.

    The opaque token itself cannot be constructed directly.
    """
    if _issuer_cap is not _ISSUER_CAP:
        raise PermissionError("invalid driver token issuer")
    return DriverToken._mint(driver_id, human_override)


@dataclass(frozen=True)
class AuditContext:
    audit_id: str
    root: str
    store: "Store"
    scope: "Scope"
    model: "ProtocolModel | None"
    budget: "Budget"
    router: Any
    home: str


class Phase(Protocol):
    name: str
    requires: list[str]
    produces: list[str]

    async def run(self, ctx: AuditContext, tok: DriverToken) -> Any: ...


class Gate(Protocol):
    def check(self, ctx: AuditContext) -> Any: ...


class Worker(Protocol):
    async def execute(self, task: Any, ctx: AuditContext) -> Any: ...


class Tool(Protocol):
    async def __call__(self, ctx: Any, **typed_args: Any) -> Any: ...


class LLMAdapter(Protocol):
    vendor: str

    def supports(self, feature: str) -> bool: ...

    async def chat(self, req: Any) -> Any: ...
