from __future__ import annotations

import ctypes
import glob
import hashlib
import json
import logging
import os
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
import uuid
from ctypes import wintypes
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.error import URLError
from urllib.request import Request, urlopen

try:
    import win32con
    import win32gui
    import win32process
    HAS_WIN32 = True
except ImportError:
    HAS_WIN32 = False

if sys.version_info < (3, 11):
    raise RuntimeError("ida-auto-mcp requires Python 3.11+ (due to MCP SDK dependency requirements).")

logger = logging.getLogger("ida_controller")
if not logger.handlers:
    logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(levelname)s: %(message)s")

DEFAULT_IDA_DIR = r"C:\Program Files\IDA Professional 9.0"
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 13337
RETENTION_PERIOD_SECONDS = 14 * 86400.0


PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
PROCESS_TERMINATE = 0x0001
SYNCHRONIZE = 0x00100000

STILL_ACTIVE = 259
WAIT_OBJECT_0 = 0x00000000
WAIT_ABANDONED = 0x00000080
WAIT_TIMEOUT = 0x00000102
WAIT_FAILED = 0xFFFFFFFF
INFINITE = 0xFFFFFFFF

ERROR_ACCESS_DENIED = 5
ERROR_INVALID_PARAMETER = 87
FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400


class FILETIME(ctypes.Structure):
    _fields_ = [
        ("dwLowDateTime", wintypes.DWORD),
        ("dwHighDateTime", wintypes.DWORD),
    ]


if sys.platform == "win32":
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE

    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL

    kernel32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
    kernel32.TerminateProcess.restype = wintypes.BOOL

    kernel32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    kernel32.GetExitCodeProcess.restype = wintypes.BOOL

    kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel32.WaitForSingleObject.restype = wintypes.DWORD

    kernel32.GetProcessTimes.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(FILETIME),
        ctypes.POINTER(FILETIME),
        ctypes.POINTER(FILETIME),
        ctypes.POINTER(FILETIME),
    ]
    kernel32.GetProcessTimes.restype = wintypes.BOOL

    kernel32.CreateMutexW.argtypes = [wintypes.LPVOID, wintypes.BOOL, wintypes.LPCWSTR]
    kernel32.CreateMutexW.restype = wintypes.HANDLE

    kernel32.ReleaseMutex.argtypes = [wintypes.HANDLE]
    kernel32.ReleaseMutex.restype = wintypes.BOOL

    try:
        kernel32.QueryFullProcessImageNameW.argtypes = [
            wintypes.HANDLE,
            wintypes.DWORD,
            wintypes.LPWSTR,
            ctypes.POINTER(wintypes.DWORD),
        ]
        kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL
        HAS_QUERY_FULL_PROCESS_IMAGE = True
    except AttributeError:
        HAS_QUERY_FULL_PROCESS_IMAGE = False
else:
    kernel32 = None
    HAS_QUERY_FULL_PROCESS_IMAGE = False


def is_reparse_point_or_symlink(path: Path | str) -> bool:
    p_str = str(path)
    try:
        if os.path.islink(p_str):
            return True
        st = os.lstat(p_str)
        attrs = getattr(st, "st_file_attributes", 0)
        if attrs & FILE_ATTRIBUTE_REPARSE_POINT:
            return True
        return False
    except (OSError, ValueError):
        return False


_IN_PROCESS_LOCK = threading.RLock()


class NamedMutex:

    def __init__(self, name: str = r"Local\ida_auto_mcp_lifecycle_mutex"):
        self.name = name
        self.handle: Optional[int] = None
        self._acquired = False
        self._owner_thread_id: Optional[int] = None
        self._recursion_count = 0
        self.was_abandoned = False

    def acquire(self, timeout_sec: float = 30.0) -> bool:
        self.was_abandoned = False
        if sys.platform != "win32" or kernel32 is None:
            self._acquired = True
            return True

        current_thread = threading.get_ident()
        if self._acquired and self._owner_thread_id == current_thread:
            self._recursion_count += 1
            return True

        if self.handle is None:
            self.handle = kernel32.CreateMutexW(None, False, self.name)
            if not self.handle:
                err = ctypes.get_last_error()
                raise OSError(f"Failed to create/open named mutex '{self.name}': error code {err}")

        timeout_ms = int(max(0.0, timeout_sec) * 1000)
        wait_res = kernel32.WaitForSingleObject(self.handle, timeout_ms)
        if wait_res == WAIT_OBJECT_0:
            self._acquired = True
            self._owner_thread_id = current_thread
            self._recursion_count = 1
            return True
        elif wait_res == WAIT_ABANDONED:
            logger.warning("Acquired abandoned lifecycle mutex '%s' (previous owner crashed)", self.name)
            self._acquired = True
            self._owner_thread_id = current_thread
            self._recursion_count = 1
            self.was_abandoned = True
            return True
        elif wait_res == WAIT_TIMEOUT:
            logger.warning("Timed out waiting for lifecycle mutex '%s' after %.1fs", self.name, timeout_sec)
            return False
        else:
            err = ctypes.get_last_error()
            raise OSError(f"WaitForSingleObject on mutex '{self.name}' failed: code {wait_res}, error {err}")

    def release(self) -> None:
        if sys.platform != "win32" or kernel32 is None:
            self._acquired = False
            return

        current_thread = threading.get_ident()
        if not self._acquired or self._owner_thread_id != current_thread:
            return

        self._recursion_count -= 1
        if self._recursion_count <= 0:
            self._recursion_count = 0
            self._acquired = False
            self._owner_thread_id = None
            if self.handle:
                try:
                    if not kernel32.ReleaseMutex(self.handle):
                        err = ctypes.get_last_error()
                        logger.error("ReleaseMutex failed for '%s': error %d", self.name, err)
                except Exception as e:
                    logger.error("Error releasing mutex '%s': %s", self.name, e)

    def close(self) -> None:
        if sys.platform != "win32" or kernel32 is None:
            return

        if self.handle:
            if self._acquired:
                self.release()
            try:
                kernel32.CloseHandle(self.handle)
            except Exception as e:
                logger.error("Error closing mutex handle '%s': %s", self.name, e)
            finally:
                self.handle = None
                self._acquired = False
                self._owner_thread_id = None
                self._recursion_count = 0
                self.was_abandoned = False


class LifecycleLock:

    def __init__(self, timeout_sec: float = 30.0, mutex_name: str = r"Local\ida_auto_mcp_lifecycle_mutex"):
        self.timeout_sec = timeout_sec
        self.mutex = NamedMutex(mutex_name)
        self._in_process_acquired = False
        self._mutex_acquired = False
        self.was_abandoned = False

    def reconcile_abandoned_state(self) -> None:
        try:
            logger.info("Reconciling system state after acquiring abandoned lifecycle mutex...")
            discover_active_instances()
        except Exception as e:
            logger.warning("Error reconciling instances after abandoned mutex: %s", e)

    def __enter__(self):
        start = time.monotonic()
        if not _IN_PROCESS_LOCK.acquire(timeout=self.timeout_sec):
            raise TimeoutError(f"Could not acquire in-process lifecycle lock within {self.timeout_sec}s")
        self._in_process_acquired = True

        elapsed = time.monotonic() - start
        remaining = max(0.1, self.timeout_sec - elapsed)
        if not self.mutex.acquire(timeout_sec=remaining):
            _IN_PROCESS_LOCK.release()
            self._in_process_acquired = False
            raise TimeoutError(f"Could not acquire OS lifecycle mutex within {self.timeout_sec}s")
        self._mutex_acquired = True
        self.was_abandoned = self.mutex.was_abandoned
        if self.was_abandoned:
            self.reconcile_abandoned_state()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        try:
            if self._mutex_acquired:
                self.mutex.release()
                self._mutex_acquired = False
        finally:
            self.mutex.close()
            if self._in_process_acquired:
                _IN_PROCESS_LOCK.release()
                self._in_process_acquired = False


@dataclass
class ManagedProcessInfo:
    pid: int
    creation_time: Optional[int]
    exe_path: Optional[str]
    host: str
    port: int
    target_path: str
    launched_at_utc: str


class ProcessTracker:
    def __init__(self):
        self._lock = threading.Lock()
        self._managed: Dict[int, ManagedProcessInfo] = {}

    def register(self, info: ManagedProcessInfo):
        with self._lock:
            self._managed[info.pid] = info

    def get(self, pid: int) -> Optional[ManagedProcessInfo]:
        with self._lock:
            return self._managed.get(pid)

    def unregister(self, pid: int):
        with self._lock:
            self._managed.pop(pid, None)

    def all_managed(self) -> List[ManagedProcessInfo]:
        with self._lock:
            return list(self._managed.values())


PROCESS_TRACKER = ProcessTracker()


def is_pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False

    if sys.platform == "win32" and kernel32 is not None:
        handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, False, pid)
        if not handle:
            err = ctypes.get_last_error()
            if err == ERROR_ACCESS_DENIED:
                return True
            if err == ERROR_INVALID_PARAMETER:
                return False
            return False

        try:
            exit_code = wintypes.DWORD()
            if kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
                if exit_code.value != STILL_ACTIVE:
                    return False
                wait_res = kernel32.WaitForSingleObject(handle, 0)
                if wait_res == WAIT_OBJECT_0:
                    return False
                elif wait_res == WAIT_TIMEOUT:
                    return True
            return True
        finally:
            kernel32.CloseHandle(handle)
    else:
        try:
            os.kill(pid, 0)
            return True
        except PermissionError:
            return True
        except (ProcessLookupError, OSError):
            return False


def get_process_creation_time(pid: int) -> Optional[int]:
    if sys.platform != "win32" or kernel32 is None or pid <= 0:
        return None

    handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        return None

    try:
        creation = FILETIME()
        exit_time = FILETIME()
        kernel_time = FILETIME()
        user_time = FILETIME()
        if kernel32.GetProcessTimes(
            handle,
            ctypes.byref(creation),
            ctypes.byref(exit_time),
            ctypes.byref(kernel_time),
            ctypes.byref(user_time),
        ):
            return (creation.dwHighDateTime << 32) | creation.dwLowDateTime
        return None
    finally:
        kernel32.CloseHandle(handle)


def get_process_executable_path(pid: int) -> Optional[str]:
    if sys.platform != "win32" or kernel32 is None or pid <= 0 or not HAS_QUERY_FULL_PROCESS_IMAGE:
        return None

    handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        return None

    try:
        buf = ctypes.create_unicode_buffer(1024)
        size = wintypes.DWORD(1024)
        if kernel32.QueryFullProcessImageNameW(handle, 0, buf, ctypes.byref(size)):
            return os.path.normpath(buf.value)
        return None
    finally:
        kernel32.CloseHandle(handle)


def is_ida_process(pid: int, expected_creation_time: Optional[int] = None) -> bool:
    if not is_pid_alive(pid):
        return False

    if expected_creation_time is not None:
        actual_ctime = get_process_creation_time(pid)
        if actual_ctime is not None and actual_ctime != expected_creation_time:
            logger.warning(
                "PID %d creation time mismatch (expected %d, got %d). PID was reused!",
                pid,
                expected_creation_time,
                actual_ctime,
            )
            return False

    exe_path = get_process_executable_path(pid)
    if exe_path:
        exe_lower = os.path.basename(exe_path).lower()
        if exe_lower in ("ida64.exe", "idat64.exe", "ida.exe", "idat.exe"):
            return True
        logger.warning("PID %d is running '%s', which is NOT an IDA executable!", pid, exe_path)
        return False

    return True


def find_windows_for_pid(pid: int) -> List[int]:
    if not HAS_WIN32:
        return []

    hwnds = []

    def enum_windows_callback(hwnd, _):
        if win32gui.IsWindow(hwnd) and win32gui.IsWindowVisible(hwnd):
            _, window_pid = win32process.GetWindowThreadProcessId(hwnd)
            if window_pid == pid:
                hwnds.append(hwnd)
        return True

    try:
        win32gui.EnumWindows(enum_windows_callback, None)
    except Exception:
        pass
    return hwnds


def get_ida_user_dir() -> str:
    if sys.platform == "win32":
        return os.path.join(os.environ.get("APPDATA", ""), "Hex-Rays", "IDA Pro")
    return os.path.join(os.path.expanduser("~"), ".idapro")


def get_instances_dir() -> str:
    return os.path.join(get_ida_user_dir(), "mcp", "instances")


def find_ida_executable(gui: bool = True) -> str:
    candidates = []

    if "IDADIR" in os.environ and os.path.isdir(os.environ["IDADIR"]):
        candidates.append(os.environ["IDADIR"])

    candidates.append(DEFAULT_IDA_DIR)

    prog_files = os.environ.get("ProgramFiles", r"C:\Program Files")
    for d in glob.glob(os.path.join(prog_files, "IDA*")):
        if os.path.isdir(d) and d not in candidates:
            candidates.append(d)

    exe_name = "ida64.exe" if gui else "idat64.exe"
    for base in candidates:
        exe_path = os.path.join(base, exe_name)
        if os.path.isfile(exe_path):
            return exe_path

    from_path = shutil.which(exe_name)
    if from_path:
        return from_path

    raise FileNotFoundError(
        f"Could not locate {exe_name}. Please ensure IDA Pro 9.0 is installed "
        f"at {DEFAULT_IDA_DIR} or set the IDADIR environment variable."
    )


def is_port_in_use(port: int = DEFAULT_PORT, host: str = DEFAULT_HOST) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        try:
            s.connect((host, port))
            return True
        except (socket.timeout, OSError):
            return False


def wait_port_released(port: int = DEFAULT_PORT, host: str = DEFAULT_HOST, timeout_sec: float = 10.0) -> bool:
    deadline = time.monotonic() + max(0.0, timeout_sec)
    while time.monotonic() < deadline:
        if not is_port_in_use(port, host):
            return True
        time.sleep(0.2)
    return not is_port_in_use(port, host)


def rpc_call(
    method: str,
    params: Optional[Dict[str, Any]] = None,
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
    timeout_sec: float = 15.0,
) -> Dict[str, Any]:
    url = f"http://{host}:{port}/mcp"
    req_id = int(time.monotonic() * 1000) % 1000000
    payload = {
        "jsonrpc": "2.0",
        "method": method,
        "params": params or {},
        "id": req_id,
    }
    data = json.dumps(payload).encode("utf-8")
    req = Request(url, data=data, headers={"Content-Type": "application/json"})
    try:
        with urlopen(req, timeout=timeout_sec) as resp:
            raw = resp.read().decode("utf-8")
            res = json.loads(raw)
            if not isinstance(res, dict):
                raise ValueError(f"Malformed JSON-RPC response from {url}: expected dict, got {type(res)}")
            return res
    except URLError as e:
        raise ConnectionError(f"Failed to communicate with IDA MCP at {url}: {e}") from e


def get_ida_health(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT, timeout_sec: float = 3.0) -> Optional[Dict[str, Any]]:
    try:
        res = rpc_call(
            "tools/call",
            {"name": "server_health", "arguments": {}},
            host=host,
            port=port,
            timeout_sec=timeout_sec,
        )
        if "error" in res:
            return None
        result = res.get("result", {})
        if result.get("isError") is True:
            return None
        return result.get("structuredContent")
    except Exception:
        return None


def is_tool_available(tool_name: str, host: str = DEFAULT_HOST, port: int = DEFAULT_PORT, timeout_sec: float = 3.0) -> bool:
    try:
        res = rpc_call("tools/list", {}, host=host, port=port, timeout_sec=timeout_sec)
        tools = res.get("result", {}).get("tools", [])
        return any(isinstance(t, dict) and t.get("name") == tool_name for t in tools)
    except Exception:
        return False


def discover_active_instances() -> List[Dict[str, Any]]:
    inst_dir = get_instances_dir()
    if not os.path.isdir(inst_dir):
        return []

    active = []
    for f in glob.glob(os.path.join(inst_dir, "instance_*.json")):
        try:
            with open(f, "r", encoding="utf-8") as fp:
                data = json.load(fp)

            pid = data.get("pid")
            host = data.get("host", DEFAULT_HOST)
            port = data.get("port", DEFAULT_PORT)

            if not pid:
                try:
                    os.unlink(f)
                except OSError:
                    pass
                continue

            if not is_pid_alive(pid) or not is_ida_process(pid):
                logger.info("Cleaning stale registration for dead or non-IDA PID %d: %s", pid, f)
                try:
                    os.unlink(f)
                except OSError:
                    pass
                continue

            active.append(data)

        except Exception as e:
            logger.warning("Error reading registration file '%s': %s", f, e)

    active.sort(key=lambda x: x.get("started_at", ""))
    return active


_FINGERPRINT_CACHE: Dict[str, Tuple[int, int, Dict[str, Any]]] = {}
_FINGERPRINT_CACHE_LOCK = threading.Lock()


def invalidate_fingerprint_cache(path: Optional[str] = None) -> None:
    with _FINGERPRINT_CACHE_LOCK:
        if path is None:
            _FINGERPRINT_CACHE.clear()
        else:
            norm = os.path.abspath(path)
            _FINGERPRINT_CACHE.pop(norm, None)


def compute_binary_fingerprint(
    binary_path: str,
    use_cache: bool = True,
    force_rehash: bool = False,
) -> Dict[str, Any]:
    norm_path = os.path.abspath(binary_path)
    stat_res = os.stat(norm_path)
    size_bytes = stat_res.st_size
    mtime_ns = stat_res.st_mtime_ns

    if use_cache and not force_rehash:
        with _FINGERPRINT_CACHE_LOCK:
            if norm_path in _FINGERPRINT_CACHE:
                cached_size, cached_mtime_ns, cached_fp = _FINGERPRINT_CACHE[norm_path]
                if cached_size == size_bytes and cached_mtime_ns == mtime_ns:
                    return cached_fp

    h = hashlib.sha256()
    with open(norm_path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    sha256_hex = h.hexdigest()

    fp = {
        "size_bytes": size_bytes,
        "mtime_ns": mtime_ns,
        "mtime_iso": datetime.fromtimestamp(stat_res.st_mtime, tz=timezone.utc).isoformat(),
        "sha256": sha256_hex,
    }

    with _FINGERPRINT_CACHE_LOCK:
        _FINGERPRINT_CACHE[norm_path] = (size_bytes, mtime_ns, fp)

    return fp


def find_loose_database_files(base_path: str) -> List[str]:
    base_no_ext, _ = os.path.splitext(base_path)
    loose_exts = (".id0", ".id1", ".id2", ".nam", ".til")
    found = []
    for ext in loose_exts:
        p = base_no_ext + ext
        if os.path.isfile(p):
            found.append(p)
    return found


def find_existing_database(file_path: str, verify_hash: bool = False) -> Tuple[Optional[str], bool, Optional[str]]:
    base, _ = os.path.splitext(file_path)
    if not os.path.isfile(file_path):
        return None, False, None

    candidates: List[str] = []
    for ext in (".i64", ".idb"):
        candidate = base + ext
        if os.path.isfile(candidate):
            candidates.append(candidate)

    if not candidates:
        return None, False, None

    chosen_db = candidates[0]
    other_db = candidates[1] if len(candidates) > 1 else None

    if len(candidates) > 1:
        mtime0 = os.path.getmtime(candidates[0])
        mtime1 = os.path.getmtime(candidates[1])
        if mtime1 > mtime0:
            chosen_db, other_db = candidates[1], candidates[0]

    is_stale = False
    sidecar_meta = os.path.splitext(chosen_db)[0] + ".ida_meta.json"

    if os.path.isfile(sidecar_meta):
        try:
            with open(sidecar_meta, "r", encoding="utf-8") as fp:
                meta = json.load(fp)
            stored_fp = meta.get("binary_fingerprint", {})
            if stored_fp and "sha256" in stored_fp:
                current_fp = compute_binary_fingerprint(file_path, force_rehash=verify_hash)
                if current_fp["sha256"] != stored_fp["sha256"]:
                    is_stale = True
        except Exception as e:
            logger.warning("Error reading database metadata sidecar '%s': %s", sidecar_meta, e)

    if not os.path.isfile(sidecar_meta) or not is_stale:
        binary_mtime = os.path.getmtime(file_path)
        db_mtime = os.path.getmtime(chosen_db)
        if binary_mtime > db_mtime:
            is_stale = True

    return chosen_db, is_stale, other_db


def get_managed_backup_dir(target_path: str) -> Path:
    custom_dir = os.environ.get("IDA_BACKUP_DIR")
    if custom_dir:
        p = Path(custom_dir).resolve()
    else:
        p = Path(target_path).resolve().parent / "ida_backups"
    p.mkdir(parents=True, exist_ok=True)
    return p


def parse_legacy_backup_timestamp(filename: str, file_path: Optional[Path] = None) -> Optional[float]:
    legacy_pattern = re.compile(r"^.+_pre_update_(\d{8}_\d{6})\.(i64|idb)$", re.IGNORECASE)
    match = legacy_pattern.match(filename)
    if not match:
        return None

    ts_str = match.group(1)
    try:
        dt_naive = datetime.strptime(ts_str, "%Y%m%d_%H%M%S")
        dt_local = dt_naive.astimezone()
        epoch_from_name = dt_local.timestamp()
    except Exception as e:
        logger.warning("Failed to parse legacy timestamp from '%s': %s", filename, e)
        return None

    if file_path and file_path.is_file():
        try:
            mtime = file_path.stat().st_mtime
            return max(epoch_from_name, mtime)
        except OSError:
            pass

    return epoch_from_name


def create_database_backup(
    binary_path: str,
    database_path: str,
    backup_dir: Optional[Path | str] = None,
) -> Dict[str, Any]:
    if is_reparse_point_or_symlink(database_path):
        return {"success": False, "error": f"Database path is a symlink or reparse point: {database_path}"}
    if is_reparse_point_or_symlink(binary_path):
        return {"success": False, "error": f"Binary path is a symlink or reparse point: {binary_path}"}
    if backup_dir and is_reparse_point_or_symlink(backup_dir):
        return {"success": False, "error": f"Backup directory path is a symlink or reparse point: {backup_dir}"}

    db_p = Path(database_path).resolve()
    bin_p = Path(binary_path).resolve()
    if not db_p.is_file():
        return {"success": False, "error": f"Database file to back up does not exist: {db_p}"}

    try:
        b_dir = Path(backup_dir).resolve() if backup_dir else get_managed_backup_dir(str(bin_p))
        b_dir.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        logger.error("Failed to create/access backup directory '%s': %s", backup_dir, e)
        return {"success": False, "error": f"Failed to create/access backup directory: {e}"}

    loose_files = find_loose_database_files(str(db_p))
    files_to_backup = [db_p] + [Path(p).resolve() for p in loose_files if os.path.isfile(p)]

    now_utc = datetime.now(timezone.utc)
    ts_str = now_utc.strftime("%Y%m%d_%H%M%S")
    unique_suffix = uuid.uuid4().hex[:8]
    backup_id = f"backup_{bin_p.stem}_{ts_str}_{unique_suffix}"

    staging_dir = b_dir / f".staging_{backup_id}"
    final_backup_dir = b_dir / backup_id

    try:
        staging_dir.mkdir(parents=True, exist_ok=False)
        active_marker = staging_dir / ".active_staging"
        marker_data = {
            "pid": os.getpid(),
            "creation_time": get_process_creation_time(os.getpid()),
            "started_at": now_utc.isoformat(),
            "backup_id": backup_id,
        }
        active_marker.write_text(json.dumps(marker_data), encoding="utf-8")

        bin_fp = compute_binary_fingerprint(str(bin_p), force_rehash=True) if bin_p.is_file() else {}

        copied_file_names: List[str] = []
        for src_file in files_to_backup:
            dest_file = staging_dir / src_file.name
            shutil.copy2(src_file, dest_file)

            if not dest_file.is_file() or dest_file.stat().st_size != src_file.stat().st_size:
                raise IOError(f"Staged file copy verification failed for {src_file.name}")

            copied_file_names.append(dest_file.name)

        meta_data = {
            "created_by": "ida-auto-mcp",
            "backup_version": "1.1.0",
            "backup_id": backup_id,
            "creation_time_utc": now_utc.isoformat(),
            "timestamp_epoch": now_utc.timestamp(),
            "original_binary_path": str(bin_p),
            "original_binary_fingerprint": bin_fp,
            "database_path": str(db_p),
            "database_format": db_p.suffix,
            "backup_files": copied_file_names,
        }
        meta_file = staging_dir / "backup_metadata.json"
        with open(meta_file, "w", encoding="utf-8") as f:
            json.dump(meta_data, f, indent=2)
            f.flush()
            os.fsync(f.fileno())

        with open(meta_file, "r", encoding="utf-8") as f:
            verified_meta = json.load(f)
            if verified_meta.get("backup_id") != backup_id:
                raise IOError("Metadata verification failed inside staging directory.")

        complete_sentinel = staging_dir / ".complete"
        complete_sentinel.write_text("COMPLETE\n", encoding="utf-8")
        if active_marker.exists():
            try:
                active_marker.unlink()
            except OSError:
                pass

        os.replace(staging_dir, final_backup_dir)

        if not final_backup_dir.is_dir() or not (final_backup_dir / ".complete").exists():
            raise IOError(f"Final backup directory verification failed: {final_backup_dir}")

        logger.info(
            "Successfully created atomic verified backup '%s' with %d files in '%s'",
            backup_id,
            len(copied_file_names),
            final_backup_dir,
        )

        try:
            cleanup_backup_retention(b_dir)
        except Exception as e:
            logger.warning("Post-backup retention cleanup encountered error: %s", e)

        return {
            "success": True,
            "backup_id": backup_id,
            "backup_dir": str(final_backup_dir),
            "backup_path": str(final_backup_dir / db_p.name),
            "metadata_path": str(final_backup_dir / "backup_metadata.json"),
            "files": copied_file_names,
        }

    except Exception as e:
        logger.error("Failed to create atomic backup for '%s': %s", database_path, e)
        if staging_dir.exists():
            shutil.rmtree(staging_dir, ignore_errors=True)
        return {"success": False, "error": str(e)}


def cleanup_backup_retention(
    backup_dir: Path | str,
    now_utc_epoch: Optional[float] = None,
) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "inspected": 0,
        "retained": 0,
        "deleted": 0,
        "failed": 0,
        "details": [],
    }

    if is_reparse_point_or_symlink(backup_dir):
        result["retained"] += 1
        result["details"].append({"path": str(backup_dir), "status": "retained", "reason": "backup_dir_is_reparse_point"})
        return result

    b_dir = Path(backup_dir).resolve()
    if not b_dir.is_dir():
        return result

    try:
        with LifecycleLock(timeout_sec=15.0):
            return _cleanup_backup_retention_locked(b_dir, now_utc_epoch=now_utc_epoch, result=result)
    except TimeoutError:
        logger.warning("Could not acquire lifecycle lock for retention cleanup within 15s; skipping retention pass.")
        return result


def _cleanup_backup_retention_locked(
    b_dir: Path,
    now_utc_epoch: Optional[float],
    result: Dict[str, Any],
) -> Dict[str, Any]:
    now = now_utc_epoch if now_utc_epoch is not None else datetime.now(timezone.utc).timestamp()
    cutoff_epoch = now - RETENTION_PERIOD_SECONDS

    for entry in b_dir.iterdir():
        if is_reparse_point_or_symlink(entry):
            result["retained"] += 1
            result["details"].append({"path": str(entry), "status": "retained", "reason": "symlink_or_reparse_point"})
            continue

        resolved_entry = entry.resolve()
        if not resolved_entry.is_relative_to(b_dir) or resolved_entry == b_dir:
            result["retained"] += 1
            result["details"].append({"path": str(entry), "status": "retained", "reason": "out_of_bounds"})
            continue

        if entry.is_dir():
            if entry.name.startswith(".staging_"):
                complete_sentinel = entry / ".complete"
                if complete_sentinel.is_file():
                    final_name = entry.name.replace(".staging_", "")
                    final_target = b_dir / final_name
                    if not final_target.exists():
                        try:
                            active_m = entry / ".active_staging"
                            if active_m.exists():
                                try:
                                    active_m.unlink()
                                except OSError:
                                    pass
                            os.replace(entry, final_target)
                            logger.info("Recovered and committed interrupted backup directory: %s -> %s", entry, final_target)
                            entry = final_target
                            resolved_entry = final_target
                        except OSError as e:
                            logger.warning("Failed to commit interrupted staging directory '%s': %s", entry, e)
                            result["retained"] += 1
                            result["details"].append({"path": str(entry), "status": "retained", "reason": "commit_recovery_failed"})
                            continue
                    else:
                        try:
                            shutil.rmtree(entry)
                            result["deleted"] += 1
                            result["details"].append({"path": str(entry), "status": "deleted", "reason": "redundant_completed_staging"})
                        except OSError as e:
                            result["failed"] += 1
                            result["details"].append({"path": str(entry), "status": "failed", "error": str(e)})
                        continue

            if entry.name.startswith(".staging_"):
                active_marker = entry / ".active_staging"
                if active_marker.is_file():
                    is_abandoned = False
                    preserve_reason = "in_progress_staging"
                    try:
                        raw_data = active_marker.read_text(encoding="utf-8").strip()
                        owner_data = {}
                        if raw_data.startswith("{"):
                            owner_data = json.loads(raw_data)
                        else:
                            for line in raw_data.splitlines():
                                if "=" in line:
                                    k, v = line.split("=", 1)
                                    owner_data[k.strip()] = v.strip()
                                    if k.strip() == "pid":
                                        try:
                                            owner_data["pid"] = int(v.strip())
                                        except ValueError:
                                            pass

                        marker_pid = int(owner_data.get("pid", 0))
                        marker_ctime = owner_data.get("creation_time")
                        if isinstance(marker_ctime, str) and marker_ctime.isdigit():
                            marker_ctime = int(marker_ctime)

                        if marker_pid <= 0:
                            preserve_reason = "missing_pid_info"
                        elif not is_pid_alive(marker_pid):
                            is_abandoned = True
                        else:
                            if marker_ctime is not None:
                                actual_ctime = get_process_creation_time(marker_pid)
                                if actual_ctime is None:
                                    preserve_reason = "process_inspection_failed"
                                elif actual_ctime == marker_ctime:
                                    preserve_reason = "active_owner_alive"
                                else:
                                    is_abandoned = True
                            else:
                                preserve_reason = "active_process_no_ctime"
                    except Exception as e:
                        logger.warning("Error reading active staging marker '%s': %s (preserving)", active_marker, e)
                        preserve_reason = "unreadable_active_staging_marker"

                    if is_abandoned:
                        try:
                            shutil.rmtree(entry)
                            logger.info("Cleaned up abandoned staging directory: %s", entry)
                            result["deleted"] += 1
                            result["details"].append({"path": str(entry), "status": "deleted", "reason": "abandoned_staging_dead_owner"})
                        except OSError as e:
                            logger.warning("Failed to remove abandoned staging directory '%s': %s", entry, e)
                            result["failed"] += 1
                            result["details"].append({"path": str(entry), "status": "failed", "error": str(e)})
                        continue
                    else:
                        result["retained"] += 1
                        result["details"].append({"path": str(entry), "status": "retained", "reason": preserve_reason})
                        continue
                else:
                    dir_age = now - entry.stat().st_mtime
                    if dir_age > 7200.0:
                        try:
                            shutil.rmtree(entry)
                            logger.info("Cleaned up stale orphaned staging directory without marker: %s", entry)
                            result["deleted"] += 1
                            result["details"].append({"path": str(entry), "status": "deleted", "reason": "orphaned_staging_no_marker"})
                        except OSError as e:
                            result["failed"] += 1
                            result["details"].append({"path": str(entry), "status": "failed", "error": str(e)})
                        continue
                    else:
                        result["retained"] += 1
                        result["details"].append({"path": str(entry), "status": "retained", "reason": "unverified_staging_ownership"})
                        continue

            meta_file = entry / "backup_metadata.json"
            if not meta_file.is_file():
                result["retained"] += 1
                result["details"].append({"path": str(entry), "status": "retained", "reason": "unrecognized_directory"})
                continue

            result["inspected"] += 1
            try:
                with open(meta_file, "r", encoding="utf-8") as f:
                    meta = json.load(f)
            except Exception as e:
                logger.warning("Unreadable metadata in '%s': %s (preserving)", entry, e)
                result["retained"] += 1
                result["details"].append({"path": str(entry), "status": "retained", "reason": f"unreadable_metadata: {e}"})
                continue

            if not isinstance(meta, dict) or meta.get("created_by") != "ida-auto-mcp":
                result["retained"] += 1
                result["details"].append({"path": str(entry), "status": "retained", "reason": "not_ida_auto_mcp"})
                continue

            ts = meta.get("timestamp_epoch")
            if ts is None and "creation_time_utc" in meta:
                try:
                    dt = datetime.fromisoformat(meta["creation_time_utc"])
                    ts = dt.timestamp()
                except Exception:
                    ts = None

            if ts is None:
                result["retained"] += 1
                result["details"].append({"path": str(entry), "status": "retained", "reason": "missing_timestamp"})
                continue

            if ts > now:
                logger.warning("Backup directory '%s' has future timestamp (ts=%.1f, now=%.1f); preserving as suspicious.", entry.name, ts, now)
                result["retained"] += 1
                result["details"].append({"path": str(entry), "status": "retained", "reason": "suspicious_future_timestamp", "timestamp": ts, "now": now})
                continue

            age_days = (now - ts) / 86400.0
            if ts < cutoff_epoch:
                try:
                    shutil.rmtree(entry)
                    logger.info("Deleted expired backup directory '%s' (age: %.1f days)", entry.name, age_days)
                    result["deleted"] += 1
                    result["details"].append({"path": str(entry), "status": "deleted", "age_days": round(age_days, 2)})
                except OSError as e:
                    logger.error("Failed to delete expired backup directory '%s': %s", entry, e)
                    result["failed"] += 1
                    result["details"].append({"path": str(entry), "status": "failed", "error": str(e), "age_days": round(age_days, 2)})
            else:
                result["retained"] += 1
                result["details"].append({"path": str(entry), "status": "retained", "age_days": round(age_days, 2), "reason": "within_14_days"})

        elif entry.is_file():
            if entry.name.startswith(".staging_") or entry.name.startswith(".tmp_") or entry.name == ".active_staging":
                continue

            result["inspected"] += 1

            legacy_ts = parse_legacy_backup_timestamp(entry.name, entry)
            if legacy_ts is not None:
                if legacy_ts > now:
                    logger.warning("Legacy backup file '%s' has future timestamp (ts=%.1f, now=%.1f); preserving as suspicious.", entry.name, legacy_ts, now)
                    result["retained"] += 1
                    result["details"].append({"path": str(entry), "status": "retained", "reason": "suspicious_future_timestamp", "timestamp": legacy_ts, "now": now})
                    continue

                age_days = (now - legacy_ts) / 86400.0
                if legacy_ts < cutoff_epoch:
                    try:
                        entry.unlink()
                        logger.info("Deleted expired legacy backup '%s' (age: %.1f days)", entry.name, age_days)
                        result["deleted"] += 1
                        result["details"].append({"path": str(entry), "status": "deleted", "age_days": round(age_days, 2)})
                    except OSError as e:
                        logger.error("Failed to delete legacy backup '%s': %s", entry, e)
                        result["failed"] += 1
                        result["details"].append({"path": str(entry), "status": "failed", "error": str(e), "age_days": round(age_days, 2)})
                else:
                    result["retained"] += 1
                    result["details"].append({"path": str(entry), "status": "retained", "age_days": round(age_days, 2), "reason": "within_14_days"})
            elif entry.name.endswith(".meta.json"):
                try:
                    with open(entry, "r", encoding="utf-8") as f:
                        meta = json.load(f)
                    ts = meta.get("timestamp_epoch")
                    if ts is not None and isinstance(meta, dict) and meta.get("created_by") == "ida-auto-mcp":
                        if ts > now:
                            result["retained"] += 1
                            result["details"].append({"path": str(entry), "status": "retained", "reason": "suspicious_future_timestamp"})
                            continue

                        age_days = (now - ts) / 86400.0
                        if ts < cutoff_epoch:
                            for bf in meta.get("backup_files", []):
                                p = b_dir / bf
                                if p.is_file() and not is_reparse_point_or_symlink(p):
                                    try:
                                        p.unlink()
                                    except OSError:
                                        pass
                            entry.unlink()
                            result["deleted"] += 1
                            result["details"].append({"path": str(entry), "status": "deleted", "age_days": round(age_days, 2)})
                        else:
                            result["retained"] += 1
                            result["details"].append({"path": str(entry), "status": "retained", "reason": "within_14_days"})
                    else:
                        result["retained"] += 1
                        result["details"].append({"path": str(entry), "status": "retained", "reason": "unrecognized_metadata"})
                except Exception:
                    result["retained"] += 1
                    result["details"].append({"path": str(entry), "status": "retained", "reason": "unreadable_metadata"})
            else:
                result["retained"] += 1
                result["details"].append({"path": str(entry), "status": "retained", "reason": "unrecognized_or_protected"})

    return result


def save_active_idb(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT, timeout_sec: float = 30.0) -> Dict[str, Any]:
    with LifecycleLock(timeout_sec=timeout_sec + 5.0):
        try:
            res = rpc_call(
                "tools/call",
                {"name": "idb_save", "arguments": {}},
                host=host,
                port=port,
                timeout_sec=timeout_sec,
            )

            if "error" in res:
                err = res["error"]
                err_msg = err.get("message", str(err)) if isinstance(err, dict) else str(err)
                return {"ok": False, "error": f"JSON-RPC error from IDA: {err_msg}"}

            result_payload = res.get("result", {})
            if not isinstance(result_payload, dict):
                return {"ok": False, "error": f"Unexpected result format from IDA: {result_payload}"}

            if result_payload.get("isError") is True:
                content_items = result_payload.get("content", [])
                err_txt = "MCP tool error during idb_save"
                if content_items and isinstance(content_items[0], dict):
                    err_txt = content_items[0].get("text", err_txt)
                return {"ok": False, "error": err_txt}

            structured = result_payload.get("structuredContent")
            if isinstance(structured, dict):
                if structured.get("ok") is False:
                    return {"ok": False, "error": structured.get("error", "idb_save reported failure")}
                saved_path = structured.get("path")
                return {"ok": True, "path": saved_path, "structuredContent": structured}

            return {"ok": True, "raw": result_payload}

        except Exception as e:
            logger.error("Failed to save active IDB on %s:%d: %s", host, port, e)
            return {"ok": False, "error": str(e)}


def close_ida_process(
    pid: int,
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
    save: bool = True,
    timeout_sec: float = 15.0,
    force: bool = False,
    expected_creation_time: Optional[int] = None,
) -> Dict[str, Any]:
    if not is_pid_alive(pid):
        PROCESS_TRACKER.unregister(pid)
        return {
            "success": True,
            "pid": pid,
            "shutdown_type": "unnecessary",
            "message": f"Process {pid} is already terminated.",
        }

    if not is_ida_process(pid, expected_creation_time=expected_creation_time):
        return {
            "success": False,
            "pid": pid,
            "shutdown_type": "failed",
            "error": f"PID {pid} is not a verified IDA process or creation time does not match.",
        }

    save_result = None
    if save and is_port_in_use(port, host):
        logger.info("Saving IDA database before closing PID %d (port %d)...", pid, port)
        save_result = save_active_idb(host=host, port=port, timeout_sec=min(timeout_sec, 20.0))
        logger.info("Save result for PID %d: %s", pid, save_result)
        if not save_result.get("ok") and not force:
            logger.error("Save failed for PID %d. Aborting shutdown to avoid data loss.", pid)
            return {
                "success": False,
                "pid": pid,
                "shutdown_type": "failed",
                "save_result": save_result,
                "error": f"Database save failed: {save_result.get('error')}. Preserving process to avoid data loss.",
            }

    hwnds = find_windows_for_pid(pid) if HAS_WIN32 else []
    graceful_attempted = False

    if hwnds:
        graceful_attempted = True
        for hwnd in hwnds:
            try:
                win32gui.PostMessage(hwnd, win32con.WM_CLOSE, 0, 0)
            except Exception:
                pass
    else:
        if is_port_in_use(port, host) and is_tool_available("py_eval", host=host, port=port):
            logger.info("Invoking ida_pro.qexit(0) via py_eval for graceful headless shutdown of PID %d...", pid)
            graceful_attempted = True
            try:
                rpc_call(
                    "tools/call",
                    {"name": "py_eval", "arguments": {"code": "import ida_pro; ida_pro.qexit(0)"}},
                    host=host,
                    port=port,
                    timeout_sec=5.0,
                )
            except Exception as e:
                logger.debug("RPC connection dropped/closed during py_eval qexit(0) for PID %d (expected): %s", pid, e)
        else:
            logger.info("py_eval tool not available on %s:%d; graceful headless shutdown cannot be requested via RPC.", host, port)

    graceful_timeout = min(timeout_sec, 8.0) if graceful_attempted else min(timeout_sec, 1.5)
    deadline = time.monotonic() + graceful_timeout
    while time.monotonic() < deadline:
        if not is_pid_alive(pid):
            break
        time.sleep(0.2)

    shutdown_type = "graceful"

    if is_pid_alive(pid):
        if force or (save_result and save_result.get("ok")) or not save:
            logger.warning(
                "IDA PID %d did not exit cleanly within %.1fs, invoking emergency TerminateProcess fallback...",
                pid,
                graceful_timeout,
            )
            if not is_ida_process(pid, expected_creation_time=expected_creation_time):
                return {
                    "success": False,
                    "pid": pid,
                    "shutdown_type": "failed",
                    "save_result": save_result,
                    "error": f"PID {pid} failed IDA identity re-verification before emergency termination (PID reuse detected).",
                }

            if sys.platform == "win32" and kernel32 is not None:
                handle = kernel32.OpenProcess(PROCESS_TERMINATE, False, pid)
                if handle:
                    try:
                        kernel32.TerminateProcess(handle, 0)
                    finally:
                        kernel32.CloseHandle(handle)
            else:
                try:
                    os.kill(pid, 9)
                except OSError:
                    pass

            term_deadline = time.monotonic() + 3.0
            while time.monotonic() < term_deadline:
                if not is_pid_alive(pid):
                    break
                time.sleep(0.2)

            if not is_pid_alive(pid):
                shutdown_type = "forced"
            else:
                return {
                    "success": False,
                    "pid": pid,
                    "shutdown_type": "failed",
                    "save_result": save_result,
                    "error": f"Failed to terminate PID {pid}.",
                }
        else:
            return {
                "success": False,
                "pid": pid,
                "shutdown_type": "failed",
                "save_result": save_result,
                "error": f"Process {pid} did not exit after graceful close signal and save was not verified.",
            }

    wait_port_released(port, host, timeout_sec=5.0)

    inst_file = os.path.join(get_instances_dir(), f"instance_{port}.json")
    if os.path.isfile(inst_file):
        try:
            with open(inst_file, "r", encoding="utf-8") as fp:
                inst_data = json.load(fp)
            if inst_data.get("pid") == pid:
                os.unlink(inst_file)
        except OSError:
            pass
        except Exception:
            pass

    PROCESS_TRACKER.unregister(pid)

    return {
        "success": True,
        "pid": pid,
        "shutdown_type": shutdown_type,
        "save_result": save_result,
        "message": f"Successfully closed IDA process {pid} ({shutdown_type}).",
    }


def close_active_target(save: bool = True, timeout_sec: float = 15.0, force: bool = False) -> Dict[str, Any]:
    with LifecycleLock(timeout_sec=timeout_sec + 5.0):
        instances = discover_active_instances()
        if not instances and not is_port_in_use(DEFAULT_PORT):
            return {"success": True, "message": "No active IDA instance found.", "instances": []}

        closed_results = []
        all_succeeded = True

        for inst in instances:
            pid = inst.get("pid")
            host = inst.get("host", DEFAULT_HOST)
            port = inst.get("port", DEFAULT_PORT)
            if pid:
                res = close_ida_process(pid=pid, host=host, port=port, save=save, timeout_sec=timeout_sec, force=force)
                closed_results.append({
                    "pid": pid,
                    "port": port,
                    "binary": inst.get("binary"),
                    "result": res,
                })
                if not res.get("success"):
                    all_succeeded = False

        return {
            "success": all_succeeded,
            "message": f"Closed {len(closed_results)} IDA instance(s).",
            "instances": closed_results,
        }


def open_target(
    target_path: str,
    gui: bool = True,
    autonomous: bool = True,
    wait_ready: bool = True,
    timeout_sec: float = 180.0,
    force_new_database: bool = False,
    auto_backup_on_update: bool = True,
) -> Dict[str, Any]:
    with LifecycleLock(timeout_sec=min(60.0, timeout_sec + 10.0)):
        norm_path = os.path.abspath(os.path.expanduser(os.path.expandvars(target_path)))
        if not os.path.isfile(norm_path):
            return {
                "success": False,
                "state": "startup_failed",
                "error": f"Target file does not exist: {norm_path}",
            }

        active_instances = discover_active_instances()
        if active_instances:
            logger.info("Existing active IDA instance detected. Saving and closing before opening new target...")
            close_res = close_active_target(save=True, timeout_sec=15.0)
            if not close_res.get("success"):
                logger.error("Failed to cleanly close existing IDA instance: %s", close_res)
                return {
                    "success": False,
                    "state": "shutdown_failed",
                    "error": "Failed to close existing IDA instance before opening new target.",
                    "details": close_res,
                }

        try:
            ida_exe = find_ida_executable(gui=gui)
        except Exception as e:
            return {
                "success": False,
                "state": "startup_failed",
                "error": str(e),
            }

        existing_idb, is_stale, other_format = find_existing_database(norm_path, verify_hash=True)
        launch_target = norm_path
        archived_backup = None

        if existing_idb and not force_new_database:
            if is_stale:
                logger.warning("Binary '%s' is newer than existing database '%s'. Binary was updated!", norm_path, existing_idb)
                if auto_backup_on_update:
                    backup_res = create_database_backup(binary_path=norm_path, database_path=existing_idb)
                    if not backup_res.get("success"):
                        return {
                            "success": False,
                            "state": "startup_failed",
                            "error": f"Failed to back up outdated database before creating fresh one: {backup_res.get('error')}",
                        }
                    archived_backup = backup_res.get("backup_path")
                    force_new_database = True
                    launch_target = norm_path
                else:
                    launch_target = existing_idb
            else:
                launch_target = existing_idb
                logger.info("Database is fresh, opening existing: %s", existing_idb)

        cmd = [ida_exe]
        if autonomous:
            cmd.append("-A")
        if force_new_database:
            cmd.append("-c")
        cmd.append(launch_target)

        logger.info("Spawning IDA: %s", " ".join(cmd))
        creationflags = 0
        if sys.platform == "win32":
            creationflags = subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP

        try:
            proc = subprocess.Popen(cmd, creationflags=creationflags)
        except Exception as e:
            return {
                "success": False,
                "state": "startup_failed",
                "error": f"Failed to launch IDA process: {e}",
            }

        proc_creation_time = get_process_creation_time(proc.pid)
        start_time = time.monotonic()
        deadline = start_time + timeout_sec

        PROCESS_TRACKER.register(
            ManagedProcessInfo(
                pid=proc.pid,
                creation_time=proc_creation_time,
                exe_path=ida_exe,
                host=DEFAULT_HOST,
                port=DEFAULT_PORT,
                target_path=launch_target,
                launched_at_utc=datetime.now(timezone.utc).isoformat(),
            )
        )

        if not wait_ready:
            return {
                "success": True,
                "state": "process_started",
                "pid": proc.pid,
                "target": launch_target,
                "was_updated": is_stale,
                "archived_backup": archived_backup,
                "message": "IDA launched (not waiting for analysis ready).",
            }

        logger.info("Waiting for IDA PID %d to register and complete auto-analysis...", proc.pid)
        mcp_ready = False
        auto_analysis_ready = False
        discovered_host = DEFAULT_HOST
        discovered_port = DEFAULT_PORT
        health_info: Optional[Dict[str, Any]] = None

        while time.monotonic() < deadline:
            if not is_pid_alive(proc.pid):
                return {
                    "success": False,
                    "state": "startup_failed",
                    "pid": proc.pid,
                    "error": f"IDA process exited unexpectedly with code {proc.poll()}.",
                }

            instances = discover_active_instances()
            my_inst = next((i for i in instances if i.get("pid") == proc.pid), None)
            if my_inst:
                discovered_host = my_inst.get("host", DEFAULT_HOST)
                discovered_port = my_inst.get("port", DEFAULT_PORT)
                health = get_ida_health(discovered_host, discovered_port, timeout_sec=2.0)
                if health and health.get("status") == "ok":
                    mcp_ready = True
                    health_info = health
                    if health.get("auto_analysis_ready") is True:
                        auto_analysis_ready = True
                        break

            time.sleep(1.0)

        if not mcp_ready:
            return {
                "success": False,
                "state": "startup_timeout",
                "pid": proc.pid,
                "port": discovered_port,
                "error": f"IDA launched (PID {proc.pid}) but MCP server was not responsive on {discovered_host}:{discovered_port} within {timeout_sec}s.",
            }

        if not auto_analysis_ready:
            return {
                "success": False,
                "state": "startup_timeout",
                "pid": proc.pid,
                "port": discovered_port,
                "mcp_ready": True,
                "auto_analysis_ready": False,
                "error": f"IDA MCP is ready on port {discovered_port}, but auto-analysis did not complete within {timeout_sec}s.",
                "health": health_info,
            }

        status_msg = (
            f"IDA Pro is open with {os.path.basename(norm_path)}. "
            f"Auto-analysis is complete."
        )
        if is_stale and archived_backup:
            status_msg += f" (Detected binary update! Previous database was archived to '{os.path.basename(archived_backup)}' and re-analyzed)."

        return {
            "success": True,
            "state": "auto_analysis_ready",
            "pid": proc.pid,
            "port": discovered_port,
            "target": launch_target,
            "binary": health_info.get("module") if health_info else os.path.basename(norm_path),
            "idb_path": health_info.get("idb_path") if health_info else None,
            "imagebase": health_info.get("imagebase") if health_info else None,
            "auto_analysis_ready": True,
            "hexrays_ready": health_info.get("hexrays_ready") if health_info else False,
            "binary_was_updated": is_stale,
            "archived_backup": archived_backup,
            "message": status_msg,
        }


def get_current_status() -> Dict[str, Any]:
    instances = discover_active_instances()
    if instances:
        first = instances[0]
        port = first.get("port", DEFAULT_PORT)
        host = first.get("host", DEFAULT_HOST)
        running = is_port_in_use(port, host)
        health = get_ida_health(host, port, timeout_sec=2.0) if running else None
    else:
        port = DEFAULT_PORT
        host = DEFAULT_HOST
        running = is_port_in_use(port, host)
        health = get_ida_health(host, port, timeout_sec=2.0) if running else None

    return {
        "mcp_server_running": running,
        "port": port,
        "instances": instances,
        "active_health": health,
        "summary": (
            f"IDA MCP is active on port {port} analyzing '{health.get('module')}'"
            if health
            else "IDA is not currently running."
        ),
    }


def list_candidate_binaries(
    directory: str,
    extensions: Optional[List[str]] = None,
    recursive: bool = False,
    max_results: int = 1000,
) -> Dict[str, Any]:
    norm_dir = os.path.abspath(os.path.expanduser(os.path.expandvars(directory)))
    if not os.path.isdir(norm_dir):
        return {"success": False, "error": f"Directory not found: {norm_dir}"}

    if extensions is None:
        exts = (".dll", ".exe", ".sys", ".so", ".bin")
    else:
        normalized = []
        for e in extensions:
            if not e:
                continue
            e_str = e.strip().lower()
            if not e_str.startswith("."):
                e_str = f".{e_str}"
            normalized.append(e_str)
        exts = tuple(normalized)

    matches = []
    total_scanned = 0
    scan_errors = []
    truncated = False

    def check_file(filepath: str):
        nonlocal total_scanned, truncated
        if len(matches) >= max_results:
            truncated = True
            return

        total_scanned += 1
        try:
            _, ext = os.path.splitext(filepath)
            if ext.lower() in exts:
                sz = os.path.getsize(filepath)
                existing_db, is_stale, _ = find_existing_database(filepath)
                matches.append({
                    "path": filepath,
                    "name": os.path.basename(filepath),
                    "size_bytes": sz,
                    "has_existing_database": existing_db is not None,
                    "database_is_outdated": is_stale,
                    "database_path": existing_db,
                })
        except OSError as e:
            scan_errors.append({"file": filepath, "error": str(e)})

    try:
        if recursive:
            for root, _, files in os.walk(norm_dir):
                if truncated:
                    break
                for f in files:
                    if truncated:
                        break
                    check_file(os.path.join(root, f))
        else:
            for entry in os.scandir(norm_dir):
                if truncated:
                    break
                try:
                    if entry.is_file():
                        check_file(entry.path)
                except OSError as e:
                    scan_errors.append({"file": entry.path, "error": str(e)})
    except OSError as e:
        return {"success": False, "error": f"Failed to scan directory {norm_dir}: {e}"}

    matches.sort(key=lambda x: x["name"])
    return {
        "success": True,
        "directory": norm_dir,
        "count": len(matches),
        "total_scanned": total_scanned,
        "truncated": truncated,
        "binaries": matches,
        "errors": scan_errors[:20],
    }
