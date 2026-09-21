from __future__ import annotations

from l0vi0x.core.interfaces import DriverToken, _issue_driver_token


def construct_driver_token(driver_id: str) -> DriverToken:
    """Construct the driver-owned capability once for a driver run."""
    return _issue_driver_token(driver_id)


def construct_human_override_token(reviewer_id: str) -> DriverToken:
    """Construct a human-override capability for an explicitly logged reviewer."""
    return _issue_driver_token(reviewer_id, human_override=True)
