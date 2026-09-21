from pathlib import Path
from l0vi0x.tools.lock import update_lock

if __name__ == "__main__":
    try:
        lock = update_lock(Path("config/tools.yaml"), Path("config/tools.lock.yaml"))
    except RuntimeError as exc:
        raise SystemExit(str(exc))
    print(f"wrote config/tools.lock.yaml for {len(lock['tools'])} tools")
