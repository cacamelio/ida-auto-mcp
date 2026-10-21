"""Client Configuration Helper for IDA Auto MCP

Updates or verifies configuration files for:
- OpenCode (~/.config/opencode/opencode.json)
- Claude Desktop (%APPDATA%/Claude/claude_desktop_config.json)
- Antigravity (~/.gemini/config/mcp_config.json)
- Cursor (~/.cursor/mcp.json)
"""

from __future__ import annotations

import json
import os
import shutil
import sys
from pathlib import Path

PYTHON_EXE = sys.executable
SERVER_SCRIPT = os.path.abspath(os.path.join(os.path.dirname(__file__), "server.py"))


def configure_opencode() -> bool:
    config_path = os.path.expanduser(r"~/.config/opencode/opencode.json")
    if not os.path.exists(config_path):
        print(f"[-] OpenCode config not found at: {config_path}")
        return False

    backup_path = config_path + ".bak"
    try:
        shutil.copy2(config_path, backup_path)
        with open(config_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        mcp_servers = data.setdefault("mcp", {})
        mcp_servers["ida-auto"] = {
            "type": "local",
            "command": [PYTHON_EXE, SERVER_SCRIPT],
            "enabled": True,
        }

        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

        print(f"[+] Configured OpenCode: {config_path}")
        return True
    except Exception as e:
        print(f"[!] Failed to configure OpenCode: {e}")
        return False


def configure_claude_desktop() -> bool:
    if sys.platform == "win32":
        config_path = os.path.expandvars(r"%APPDATA%\Claude\claude_desktop_config.json")
    else:
        config_path = os.path.expanduser("~/Library/Application Support/Claude/claude_desktop_config.json")

    os.makedirs(os.path.dirname(config_path), exist_ok=True)
    backup_path = config_path + ".bak"
    try:
        data = {"mcpServers": {}}
        if os.path.exists(config_path):
            shutil.copy2(config_path, backup_path)
            with open(config_path, "r", encoding="utf-8") as f:
                data = json.load(f)

        mcp_servers = data.setdefault("mcpServers", {})
        mcp_servers["ida-auto"] = {
            "command": PYTHON_EXE,
            "args": [SERVER_SCRIPT],
        }

        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

        print(f"[+] Configured Claude Desktop: {config_path}")
        return True
    except Exception as e:
        print(f"[!] Failed to configure Claude Desktop: {e}")
        return False


def configure_antigravity() -> bool:
    config_path = os.path.expanduser(r"~/.gemini/config/mcp_config.json")
    os.makedirs(os.path.dirname(config_path), exist_ok=True)

    backup_path = config_path + ".bak"
    try:
        data = {"mcpServers": {}}
        if os.path.exists(config_path):
            shutil.copy2(config_path, backup_path)
            with open(config_path, "r", encoding="utf-8") as f:
                data = json.load(f)

        mcp_servers = data.setdefault("mcpServers", {})
        mcp_servers["ida-auto"] = {
            "command": PYTHON_EXE,
            "args": [SERVER_SCRIPT],
        }

        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

        print(f"[+] Configured Antigravity: {config_path}")
        return True
    except Exception as e:
        print(f"[!] Failed to configure Antigravity: {e}")
        return False


def main():
    print("=== IDA Auto MCP Client Setup ===")
    print(f"Python: {PYTHON_EXE}")
    print(f"Script: {SERVER_SCRIPT}\n")

    configure_opencode()
    configure_claude_desktop()
    configure_antigravity()

    print("\nRestart your AI client (OpenCode, Claude, etc.) to activate the new tools.")


if __name__ == "__main__":
    main()
