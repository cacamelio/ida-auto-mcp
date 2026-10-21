"""IDA Pro Process and Automation Controller

Manages the lifecycle of IDA Pro instances, interacts with the embedded
ida_mcp plugin (on 127.0.0.1:13337), and automates opening, switching,
and saving databases for LLM-driven static analysis pipelines.
"""

from __future__ import annotations

import glob
import json
import logging
import os
import shutil
import socket
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.error import URLError
from urllib.request import Request, urlopen

try:
    import win32con
    import win32gui
    import win32process
    HAS_WIN32 = True
except ImportError:
    HAS_WIN32 = False

logger = logging.getLogger("ida_controller")
logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(levelname)s: %(message)s")

DEFAULT_IDA_DIR = r"C:\Program Files\IDA Professional 9.0"
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 13337


def get_ida_user_dir() -> str:
    """Return the user configuration directory for IDA Pro."""
    if sys.platform == "win32":
        return os.path.join(os.environ.get("APPDATA", ""), "Hex-Rays", "IDA Pro")
    return os.path.join(os.path.expanduser("~"), ".idapro")


def get_instances_dir() -> str:
    """Return the directory where ida_mcp instances register themselves."""
    return os.path.join(get_ida_user_dir(), "mcp", "instances")


def find_ida_executable(gui: bool = True) -> str:
    """Locate the IDA 9.0 executable on the system."""
    candidates = []

    # Check environment variable if set
    if "IDADIR" in os.environ and os.path.isdir(os.environ["IDADIR"]):
        candidates.append(os.environ["IDADIR"])

    candidates.append(DEFAULT_IDA_DIR)

    # Check Program Files for any IDA installations
    prog_files = os.environ.get("ProgramFiles", r"C:\Program Files")
    for d in glob.glob(os.path.join(prog_files, "IDA*")):
        if os.path.isdir(d) and d not in candidates:
            candidates.append(d)

    exe_name = "ida64.exe" if gui else "idat64.exe"
    for base in candidates:
        exe_path = os.path.join(base, exe_name)
        if os.path.isfile(exe_path):
            return exe_path

    # Fallback to PATH
    from_path = shutil.which(exe_name)
    if from_path:
        return from_path

    raise FileNotFoundError(
        f"Could not locate {exe_name}. Please ensure IDA Pro 9.0 is installed "
        f"at {DEFAULT_IDA_DIR} or set the IDADIR environment variable."
    )


def is_port_in_use(port: int = DEFAULT_PORT, host: str = DEFAULT_HOST) -> bool:
    """Check if the given TCP port is currently open and bound."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        try:
            s.connect((host, port))
            return True
        except (socket.timeout, OSError):
            return False


def wait_port_released(port: int = DEFAULT_PORT, host: str = DEFAULT_HOST, timeout_sec: float = 10.0) -> bool:
    """Wait until a TCP port is completely released."""
    deadline = time.time() + timeout_sec
    while time.time() < deadline:
        if not is_port_in_use(port, host):
            return True
        time.sleep(0.3)
    return not is_port_in_use(port, host)


def rpc_call(
    method: str,
    params: Optional[Dict[str, Any]] = None,
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
    timeout_sec: float = 15.0,
) -> Dict[str, Any]:
    """Execute a JSON-RPC 2.0 tool call against IDA's embedded ida_mcp server."""
    url = f"http://{host}:{port}/mcp"
    payload = {
        "jsonrpc": "2.0",
        "method": method,
        "params": params or {},
        "id": int(time.time() * 1000) % 100000,
    }
    data = json.dumps(payload).encode("utf-8")
    req = Request(url, data=data, headers={"Content-Type": "application/json"})
    try:
        with urlopen(req, timeout=timeout_sec) as resp:
            raw = resp.read().decode("utf-8")
            return json.loads(raw)
    except URLError as e:
        raise ConnectionError(f"Failed to communicate with IDA MCP at {url}: {e}") from e


def get_ida_health(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT, timeout_sec: float = 3.0) -> Optional[Dict[str, Any]]:
    """Query IDA's server_health tool via RPC."""
    try:
        res = rpc_call(
            "tools/call",
            {"name": "server_health", "arguments": {}},
            host=host,
            port=port,
            timeout_sec=timeout_sec,
        )
        if "result" in res and "structuredContent" in res["result"]:
            return res["result"]["structuredContent"]
        return None
    except Exception:
        return None


def discover_active_instances() -> List[Dict[str, Any]]:
    """Scan the IDA instance registration directory and return active instances."""
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

            # Check if process exists and port is reachable
            if pid and is_pid_alive(pid) and is_port_in_use(port, host):
                active.append(data)
            else:
                # Clean up stale registration
                try:
                    os.unlink(f)
                except OSError:
                    pass
        except Exception:
            pass
    return active


def is_pid_alive(pid: int) -> bool:
    """Check if process ID is still alive."""
    if pid <= 0:
        return False
    if sys.platform == "win32":
        try:
            import ctypes
            PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
            handle = ctypes.windll.kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
            if handle:
                ctypes.windll.kernel32.CloseHandle(handle)
                return True
            return False
        except Exception:
            return False
    else:
        try:
            os.kill(pid, 0)
            return True
        except OSError:
            return False


def find_windows_for_pid(pid: int) -> List[int]:
    """Find all top-level window handles belonging to a process ID."""
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


def save_active_idb(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT, timeout_sec: float = 30.0) -> Dict[str, Any]:
    """Instruct the active IDA instance to save its database (.i64/.idb)."""
    try:
        res = rpc_call(
            "tools/call",
            {"name": "idb_save", "arguments": {}},
            host=host,
            port=port,
            timeout_sec=timeout_sec,
        )
        if "result" in res and "structuredContent" in res["result"]:
            return res["result"]["structuredContent"]
        return {"ok": True, "raw": res}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def close_ida_process(pid: int, save: bool = True, timeout_sec: float = 15.0) -> bool:
    """Cleanly close an IDA process by PID."""
    if not is_pid_alive(pid):
        return True

    # 1. Save database if requested and IDA MCP is alive
    if save and is_port_in_use(DEFAULT_PORT):
        logger.info("Saving IDA database before closing PID %d...", pid)
        save_res = save_active_idb(timeout_sec=10.0)
        logger.info("Save result: %s", save_res)

    # 2. Try sending WM_CLOSE to IDA GUI windows
    if HAS_WIN32:
        hwnds = find_windows_for_pid(pid)
        for hwnd in hwnds:
            try:
                win32gui.PostMessage(hwnd, win32con.WM_CLOSE, 0, 0)
            except Exception:
                pass

    # Wait for clean exit
    deadline = time.time() + min(timeout_sec, 6.0)
    while time.time() < deadline:
        if not is_pid_alive(pid):
            break
        time.sleep(0.3)

    # 3. If still alive, terminate firmly
    if is_pid_alive(pid):
        logger.warning("IDA PID %d did not exit after close request, terminating process...", pid)
        if sys.platform == "win32":
            try:
                import ctypes
                PROCESS_TERMINATE = 0x0001
                handle = ctypes.windll.kernel32.OpenProcess(PROCESS_TERMINATE, False, pid)
                if handle:
                    ctypes.windll.kernel32.TerminateProcess(handle, 0)
                    ctypes.windll.kernel32.CloseHandle(handle)
            except Exception as e:
                logger.error("Failed to terminate PID %d: %s", pid, e)
        else:
            try:
                os.kill(pid, 9)
            except OSError:
                pass

    # 4. Wait for port release and file cleanup
    wait_port_released(DEFAULT_PORT, timeout_sec=5.0)

    # Clean instance registration file
    inst_file = os.path.join(get_instances_dir(), f"instance_{DEFAULT_PORT}.json")
    if os.path.isfile(inst_file):
        try:
            os.unlink(inst_file)
        except OSError:
            pass

    return not is_pid_alive(pid)


def close_active_target(save: bool = True, timeout_sec: float = 15.0) -> Dict[str, Any]:
    """Close any currently running IDA instance."""
    instances = discover_active_instances()
    if not instances:
        if not is_port_in_use(DEFAULT_PORT):
            return {"success": True, "message": "No active IDA instance found."}

    closed_pids = []
    for inst in instances:
        pid = inst.get("pid")
        if pid:
            ok = close_ida_process(pid, save=save, timeout_sec=timeout_sec)
            closed_pids.append({"pid": pid, "closed": ok, "binary": inst.get("binary")})

    wait_port_released(DEFAULT_PORT, timeout_sec=5.0)
    return {
        "success": True,
        "message": f"Closed {len(closed_pids)} IDA instance(s).",
        "instances": closed_pids,
    }


def find_existing_database(file_path: str) -> Optional[str]:
    """Find an existing .i64 or .idb adjacent to the target file."""
    base, _ = os.path.splitext(file_path)
    for ext in (".i64", ".idb"):
        candidate = base + ext
        if os.path.isfile(candidate):
            return candidate
    return None


def open_target(
    target_path: str,
    gui: bool = True,
    autonomous: bool = True,
    wait_ready: bool = True,
    timeout_sec: float = 180.0,
    force_new_database: bool = False,
) -> Dict[str, Any]:
    """Launch IDA Pro with the specified target file and wait for analysis/MCP readiness."""
    norm_path = os.path.abspath(os.path.expanduser(os.path.expandvars(target_path)))
    if not os.path.isfile(norm_path):
        return {
            "success": False,
            "error": f"Target file does not exist: {norm_path}",
        }

    # 1. If another IDA instance is active, close and save it first
    active = discover_active_instances()
    if active or is_port_in_use(DEFAULT_PORT):
        logger.info("Existing IDA instance detected. Saving and closing before opening new target...")
        close_active_target(save=True)

    # 2. Locate IDA executable
    ida_exe = find_ida_executable(gui=gui)

    # 3. Determine target: prefer existing .i64/.idb database if available
    launch_target = norm_path
    if not force_new_database:
        existing_idb = find_existing_database(norm_path)
        if existing_idb:
            launch_target = existing_idb
            logger.info("Reusing existing database: %s", existing_idb)

    # 4. Construct command line flags
    # -A : autonomous mode (suppresses modal dialogs/prompts)
    # -c : create new database if requested
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

    proc = subprocess.Popen(cmd, creationflags=creationflags)
    start_time = time.time()
    deadline = start_time + timeout_sec

    if not wait_ready:
        return {
            "success": True,
            "pid": proc.pid,
            "target": launch_target,
            "message": "IDA launched (not waiting for analysis ready).",
        }

    # 5. Wait for IDA to start, initialize ida_mcp, and complete auto-analysis
    logger.info("Waiting for IDA MCP to respond on port %d...", DEFAULT_PORT)
    mcp_ready = False
    auto_analysis_ready = False
    health_info: Optional[Dict[str, Any]] = None

    while time.time() < deadline:
        if not is_pid_alive(proc.pid):
            return {
                "success": False,
                "error": f"IDA process exited unexpectedly with code {proc.poll()}.",
            }

        if is_port_in_use(DEFAULT_PORT):
            health = get_ida_health(DEFAULT_HOST, DEFAULT_PORT, timeout_sec=2.0)
            if health and health.get("status") == "ok":
                mcp_ready = True
                health_info = health
                if health.get("auto_analysis_ready") is True:
                    auto_analysis_ready = True
                    break

        time.sleep(1.5)

    if not mcp_ready:
        return {
            "success": False,
            "pid": proc.pid,
            "error": f"IDA launched but ida_mcp did not become responsive on port {DEFAULT_PORT} within {timeout_sec}s.",
        }

    return {
        "success": True,
        "pid": proc.pid,
        "port": DEFAULT_PORT,
        "target": launch_target,
        "binary": health_info.get("module") if health_info else os.path.basename(norm_path),
        "idb_path": health_info.get("idb_path") if health_info else None,
        "imagebase": health_info.get("imagebase") if health_info else None,
        "auto_analysis_ready": auto_analysis_ready,
        "hexrays_ready": health_info.get("hexrays_ready") if health_info else False,
        "message": (
            f"IDA Pro is open with {os.path.basename(norm_path)}. "
            f"Auto-analysis is {'complete' if auto_analysis_ready else 'in progress'}. "
            "You can now use all IDA MCP tools (decompile, list_funcs, survey_binary, etc.)."
        ),
    }


def get_current_status() -> Dict[str, Any]:
    """Get the current operational status of IDA Pro and the MCP plugin."""
    running = is_port_in_use(DEFAULT_PORT)
    instances = discover_active_instances()
    health = get_ida_health(DEFAULT_HOST, DEFAULT_PORT, timeout_sec=2.0) if running else None

    return {
        "mcp_server_running": running,
        "port": DEFAULT_PORT,
        "instances": instances,
        "active_health": health,
        "summary": (
            f"IDA MCP is active on port {DEFAULT_PORT} analyzing '{health.get('module')}'"
            if health
            else "IDA is not currently running."
        ),
    }


def list_candidate_binaries(
    directory: str,
    extensions: Optional[List[str]] = None,
    recursive: bool = False,
) -> Dict[str, Any]:
    """Scan a directory for binaries suitable for IDA static analysis."""
    norm_dir = os.path.abspath(os.path.expanduser(os.path.expandvars(directory)))
    if not os.path.isdir(norm_dir):
        return {"success": False, "error": f"Directory not found: {norm_dir}"}

    exts = tuple(e.lower() for e in (extensions or [".dll", ".exe", ".sys", ".so", ".bin"]))
    matches = []

    def check_file(filepath: str):
        _, ext = os.path.splitext(filepath)
        if ext.lower() in exts:
            sz = os.path.getsize(filepath)
            has_idb = find_existing_database(filepath) is not None
            matches.append({
                "path": filepath,
                "name": os.path.basename(filepath),
                "size_bytes": sz,
                "has_existing_database": has_idb,
            })

    if recursive:
        for root, _, files in os.walk(norm_dir):
            for f in files:
                check_file(os.path.join(root, f))
    else:
        for entry in os.scandir(norm_dir):
            if entry.is_file():
                check_file(entry.path)

    matches.sort(key=lambda x: x["name"])
    return {
        "success": True,
        "directory": norm_dir,
        "count": len(matches),
        "binaries": matches,
    }
