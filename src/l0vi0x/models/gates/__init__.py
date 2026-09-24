"""Hard gates that refuse routing outright -- terms/pricing/privacy
(M2.5), authorization/stack-selection boundaries (M2.6). Each gate
mirrors `core.policy.CheatcodePolicy`'s shape (a YAML-driven rules file
plus a typed exception) deliberately, rather than a bespoke idiom per
gate.
"""
from .authorization import AuthorizationContextMissing, AuthorizationGate, StackSelectionDenied

__all__ = ["AuthorizationContextMissing", "AuthorizationGate", "StackSelectionDenied"]
