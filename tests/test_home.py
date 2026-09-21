import os

from l0vi0x.core.home import ensure_audit_key, ensure_home


def test_external_home_and_audit_key_permissions(tmp_path):
    root = ensure_home(tmp_path / "home")
    assert oct(os.stat(root).st_mode & 0o777) == "0o700"
    key = ensure_audit_key("AUDIT-1", root)
    assert key.exists()
    assert len(key.read_bytes()) == 32
    assert oct(os.stat(key).st_mode & 0o777) == "0o600"
