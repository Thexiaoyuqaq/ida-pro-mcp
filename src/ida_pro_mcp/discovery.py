import os
import sys
import json
import time
import errno
import hashlib
import tempfile
from dataclasses import dataclass, asdict
from glob import glob

# Shared registry location (must match the inlined writer in mcp-plugin.py)
REGISTRY_DIR = os.path.join(tempfile.gettempdir(), "ida-pro-mcp", "instances")

# An entry is considered stale if its heartbeat is older than this many seconds.
HEARTBEAT_TIMEOUT = 30.0


@dataclass
class InstanceInfo:
    """Describes a single discoverable IDA endpoint."""
    id: str
    host: str
    port: int
    idb_path: str
    module: str
    pid: int
    kind: str  # "gui" | "idalib"
    started_at: float
    heartbeat: float

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "InstanceInfo":
        # Tolerate missing/extra keys so schema evolution never breaks discovery.
        return cls(
            id=str(d["id"]),
            host=str(d.get("host", "127.0.0.1")),
            port=int(d["port"]),
            idb_path=str(d.get("idb_path", "")),
            module=str(d.get("module", "")),
            pid=int(d.get("pid", 0)),
            kind=str(d.get("kind", "gui")),
            started_at=float(d.get("started_at", 0.0)),
            heartbeat=float(d.get("heartbeat", 0.0)),
        )


def make_id(idb_path: str, port: int) -> str:
    """Unique-per-instance id.

    The port is included so that opening the *same* database in multiple IDA
    instances yields distinct ids (ports are unique among live local instances).
    """
    if idb_path:
        norm = os.path.normcase(os.path.abspath(idb_path))
        digest = hashlib.sha1(norm.encode("utf-8", "replace")).hexdigest()[:8]
        return f"{digest}-{port}"
    return f"port{port}"


def _ensure_dir() -> None:
    os.makedirs(REGISTRY_DIR, exist_ok=True)


def _path_for(instance_id: str) -> str:
    return os.path.join(REGISTRY_DIR, f"{instance_id}.json")


def _atomic_write(path: str, data: dict) -> None:
    _ensure_dir()
    fd, tmp = tempfile.mkstemp(dir=REGISTRY_DIR, prefix=".tmp_", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def register(info: InstanceInfo) -> None:
    """Write (or overwrite) the registry entry for an instance."""
    _atomic_write(_path_for(info.id), info.to_dict())


def heartbeat(instance_id: str) -> None:
    """Refresh the heartbeat timestamp for an instance (best effort)."""
    path = _path_for(instance_id)
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        data["heartbeat"] = time.time()
        _atomic_write(path, data)
    except (OSError, ValueError):
        pass


def unregister(instance_id: str) -> None:
    """Remove an instance's registry entry (best effort)."""
    try:
        os.unlink(_path_for(instance_id))
    except OSError:
        pass


def _pid_alive(pid: int) -> bool:
    """Whether a process is alive. Safe on Windows (never terminates)."""
    if pid <= 0:
        return True  # unknown pid -> don't prune on this signal alone
    if sys.platform == "win32":
        import ctypes

        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        STILL_ACTIVE = 259
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not handle:
            return False
        try:
            exit_code = ctypes.c_ulong()
            ok = kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code))
            if not ok:
                return True
            return exit_code.value == STILL_ACTIVE
        finally:
            kernel32.CloseHandle(handle)
    else:
        try:
            os.kill(pid, 0)
        except OSError as e:
            if e.errno == errno.ESRCH:
                return False
            return True  # EPERM etc. -> exists
        return True


def discover(prune: bool = True) -> list[InstanceInfo]:
    """Return all live instances, pruning stale/dead entries from disk."""
    result: list[InstanceInfo] = []
    now = time.time()
    _ensure_dir()
    for path in glob(os.path.join(REGISTRY_DIR, "*.json")):
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            info = InstanceInfo.from_dict(data)
        except (OSError, ValueError, KeyError):
            continue  # tolerate partial/corrupt/locked files

        stale = bool(info.heartbeat) and (now - info.heartbeat) > HEARTBEAT_TIMEOUT
        dead = not _pid_alive(info.pid)
        if stale or dead:
            if prune:
                try:
                    os.unlink(path)
                except OSError:
                    pass
            continue
        result.append(info)

    result.sort(key=lambda i: i.port)
    return result
