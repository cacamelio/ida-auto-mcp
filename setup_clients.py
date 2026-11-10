from __future__ import annotations

import json
import logging
import os
import shutil
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict

if sys.version_info < (3, 11):
    raise RuntimeError("ida-auto-mcp requires Python 3.11+ (due to MCP SDK dependency requirements).")

logger = logging.getLogger("ida_setup_clients")
logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(levelname)s: %(message)s")

PYTHON_EXE = sys.executable
SERVER_SCRIPT = os.path.abspath(os.path.join(os.path.dirname(__file__), "server.py"))


def safe_update_json_config(config_path_str: str, update_fn: Callable[[Dict[str, Any]], None]) -> bool:
    config_path = Path(os.path.abspath(os.path.expanduser(os.path.expandvars(config_path_str))))
    parent_dir = config_path.parent

    try:
        parent_dir.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        print(f"[!] Failed to create parent directory '{parent_dir}': {e}")
        return False

    data: Dict[str, Any] = {}
    timestamp_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    if config_path.is_file():
        backup_path = parent_dir / f"{config_path.name}.bak.{timestamp_str}"
        try:
            shutil.copy2(config_path, backup_path)
            print(f"[*] Created backup: {backup_path}")
        except OSError as e:
            print(f"[!] Failed to create backup before modifying '{config_path}': {e}")
            return False

        try:
            with open(config_path, "r", encoding="utf-8") as f:
                loaded = json.load(f)
                if isinstance(loaded, dict):
                    data = loaded
                else:
                    print(f"[!] Config '{config_path}' was not a JSON object, initializing new object.")
        except Exception as e:
            corrupt_path = parent_dir / f"{config_path.name}.corrupt.{timestamp_str}"
            try:
                shutil.copy2(config_path, corrupt_path)
                print(f"[!] Existing JSON was invalid ({e}). Preserved corrupt copy at: {corrupt_path}")
            except OSError:
                pass
            data = {}

    try:
        update_fn(data)
    except Exception as e:
        print(f"[!] Error applying configuration updates: {e}")
        return False

    tmp_path = parent_dir / f".{config_path.name}.tmp_{uuid.uuid4().hex[:8]}"
    try:
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
            f.flush()
            os.fsync(f.fileno())

        with open(tmp_path, "r", encoding="utf-8") as f:
            verified_data = json.load(f)
            if not isinstance(verified_data, dict):
                raise ValueError("Verification failed: written file is not a valid JSON dict.")

        os.replace(tmp_path, config_path)

        if not config_path.is_file() or config_path.stat().st_size == 0:
            raise IOError("Target config file missing or empty after atomic replacement.")

        print(f"[+] Successfully updated configuration: {config_path}")
        return True

    except Exception as e:
        print(f"[!] Failed to write updated config for '{config_path}': {e}")
        if tmp_path.exists():
            try:
                tmp_path.unlink()
            except OSError:
                pass
        return False


def get_opencode_config_path() -> str:
    if sys.platform == "win32":
        return os.path.expandvars(r"%USERPROFILE%\.config\opencode\opencode.json")
    return os.path.expanduser("~/.config/opencode/opencode.json")


def configure_opencode() -> bool:
    config_path = get_opencode_config_path()

    def updater(data: Dict[str, Any]) -> None:
        mcp_servers = data.setdefault("mcp", {})
        mcp_servers["ida-auto"] = {
            "type": "local",
            "command": [PYTHON_EXE, SERVER_SCRIPT],
            "enabled": True,
        }

    return safe_update_json_config(config_path, updater)


def get_claude_desktop_config_path() -> str:
    if sys.platform == "win32":
        return os.path.expandvars(r"%APPDATA%\Claude\claude_desktop_config.json")
    elif sys.platform == "darwin":
        return os.path.expanduser("~/Library/Application Support/Claude/claude_desktop_config.json")
    else:
        return os.path.expanduser("~/.config/Claude/claude_desktop_config.json")


def configure_claude_desktop() -> bool:
    config_path = get_claude_desktop_config_path()

    def updater(data: Dict[str, Any]) -> None:
        mcp_servers = data.setdefault("mcpServers", {})
        mcp_servers["ida-auto"] = {
            "command": PYTHON_EXE,
            "args": [SERVER_SCRIPT],
        }

    return safe_update_json_config(config_path, updater)


def get_antigravity_config_path() -> str:
    if sys.platform == "win32":
        return os.path.expandvars(r"%USERPROFILE%\.gemini\config\mcp_config.json")
    return os.path.expanduser("~/.gemini/config/mcp_config.json")


def configure_antigravity() -> bool:
    config_path = get_antigravity_config_path()

    def updater(data: Dict[str, Any]) -> None:
        mcp_servers = data.setdefault("mcpServers", {})
        mcp_servers["ida-auto"] = {
            "command": PYTHON_EXE,
            "args": [SERVER_SCRIPT],
        }

    return safe_update_json_config(config_path, updater)


def get_cursor_config_path() -> str:
    if sys.platform == "win32":
        return os.path.expandvars(r"%USERPROFILE%\.cursor\mcp.json")
    return os.path.expanduser("~/.cursor/mcp.json")


def configure_cursor() -> bool:
    config_path = get_cursor_config_path()

    def updater(data: Dict[str, Any]) -> None:
        mcp_servers = data.setdefault("mcpServers", {})
        mcp_servers["ida-auto"] = {
            "command": PYTHON_EXE,
            "args": [SERVER_SCRIPT],
        }

    return safe_update_json_config(config_path, updater)


def main():
    print("=== IDA Auto MCP Client Setup ===")
    print(f"Python: {PYTHON_EXE}")
    print(f"Script: {SERVER_SCRIPT}\n")

    results = {
        "OpenCode": configure_opencode(),
        "Claude Desktop": configure_claude_desktop(),
        "Antigravity": configure_antigravity(),
        "Cursor": configure_cursor(),
    }

    print("\nConfiguration Summary:")
    for client, ok in results.items():
        status = "CONFIGURED" if ok else "FAILED"
        print(f"  - {client}: {status}")

    print("\nRestart your AI client (OpenCode, Claude, Cursor, Antigravity) to activate the new tools.")


if __name__ == "__main__":
    main()
