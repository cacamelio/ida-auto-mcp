from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

if sys.version_info < (3, 11):
    raise RuntimeError("ida-auto-mcp requires Python 3.11+ (due to MCP SDK dependency requirements).")

from mcp.server.mcpserver import MCPServer

from ida_controller import (
    close_active_target,
    get_current_status,
    list_candidate_binaries,
    open_target,
    save_active_idb,
)

logger = logging.getLogger("ida_auto_mcp")
if not logger.handlers:
    logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(levelname)s: %(message)s")

mcp = MCPServer(
    name="ida-auto-mcp",
    version="1.1.0",
    description="Automate opening, closing, and switching binaries in IDA Pro for unattended static analysis.",
)


def _validate_path(path_str: str) -> str:
    if not path_str or not isinstance(path_str, str) or not path_str.strip():
        raise ValueError("Path must be a non-empty string.")
    cleaned = path_str.strip()
    norm = os.path.abspath(os.path.expanduser(os.path.expandvars(cleaned)))
    return norm


@mcp.tool(description="Open a binary or database in IDA Pro and wait for auto-analysis and MCP readiness.")
def ida_open(
    target_path: str,
    gui: bool = True,
    autonomous: bool = True,
    wait_ready: bool = True,
    timeout_sec: int = 180,
    force_new_database: bool = False,
    auto_backup_on_update: bool = True,
) -> Dict[str, Any]:
    try:
        norm_path = _validate_path(target_path)
        valid_timeout = max(1.0, float(timeout_sec))
        return open_target(
            target_path=norm_path,
            gui=bool(gui),
            autonomous=bool(autonomous),
            wait_ready=bool(wait_ready),
            timeout_sec=valid_timeout,
            force_new_database=bool(force_new_database),
            auto_backup_on_update=bool(auto_backup_on_update),
        )
    except Exception as e:
        logger.error("ida_open error for '%s': %s", target_path, e)
        return {
            "success": False,
            "state": "startup_failed",
            "error": str(e),
        }


@mcp.tool(description="Gracefully save the database and close the currently running IDA Pro instance.")
def ida_close(save: bool = True, timeout_sec: int = 15) -> Dict[str, Any]:
    try:
        valid_timeout = max(1.0, float(timeout_sec))
        return close_active_target(save=bool(save), timeout_sec=valid_timeout)
    except Exception as e:
        logger.error("ida_close error: %s", e)
        return {
            "success": False,
            "error": str(e),
        }


@mcp.tool(description="Switch to a different target: automatically saves the current IDA database, closes it, and opens the new binary.")
def ida_switch(
    target_path: str,
    gui: bool = True,
    autonomous: bool = True,
    wait_ready: bool = True,
    timeout_sec: int = 180,
    force_new_database: bool = False,
    auto_backup_on_update: bool = True,
) -> Dict[str, Any]:
    try:
        norm_path = _validate_path(target_path)
        valid_timeout = max(1.0, float(timeout_sec))
        return open_target(
            target_path=norm_path,
            gui=bool(gui),
            autonomous=bool(autonomous),
            wait_ready=bool(wait_ready),
            timeout_sec=valid_timeout,
            force_new_database=bool(force_new_database),
            auto_backup_on_update=bool(auto_backup_on_update),
        )
    except Exception as e:
        logger.error("ida_switch error for '%s': %s", target_path, e)
        return {
            "success": False,
            "state": "startup_failed",
            "error": str(e),
        }


@mcp.tool(description="Check the status of IDA Pro, the active target binary, auto-analysis progress, and MCP server health.")
def ida_status() -> Dict[str, Any]:
    try:
        return get_current_status()
    except Exception as e:
        logger.error("ida_status error: %s", e)
        return {
            "mcp_server_running": False,
            "summary": "Error checking status",
            "error": str(e),
        }


@mcp.tool(description="Save the currently open IDA database to disk without closing IDA.")
def ida_save() -> Dict[str, Any]:
    try:
        return save_active_idb()
    except Exception as e:
        logger.error("ida_save error: %s", e)
        return {
            "ok": False,
            "error": str(e),
        }


@mcp.tool(description="Scan a folder for candidate binary files to analyze in IDA.")
def ida_list_targets(
    directory: str,
    extensions: Optional[List[str]] = None,
    recursive: bool = False,
) -> Dict[str, Any]:
    try:
        norm_dir = _validate_path(directory)
        return list_candidate_binaries(
            directory=norm_dir,
            extensions=extensions,
            recursive=bool(recursive),
        )
    except Exception as e:
        logger.error("ida_list_targets error for '%s': %s", directory, e)
        return {
            "success": False,
            "error": str(e),
        }


def main():
    parser = argparse.ArgumentParser(description="IDA Auto MCP Server")
    parser.add_argument(
        "--transport",
        choices=["stdio", "sse", "streamable-http"],
        default="stdio",
        help="MCP transport protocol (default: stdio)",
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Host for HTTP/SSE transport (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8746,
        help="Port for HTTP/SSE transport (default: 8746)",
    )
    args = parser.parse_args()

    LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}
    if args.host not in LOOPBACK_HOSTS:
        parser.error(
            f"Binding to non-loopback host '{args.host}' is prohibited for security. "
            "ida-auto-mcp tools control operating system processes and database files, "
            "and unauthenticated remote access is not supported. Use 127.0.0.1 or localhost."
        )

    if args.transport == "stdio":
        mcp.run("stdio")
    elif args.transport == "sse":
        mcp.run("sse", host=args.host, port=args.port)
    elif args.transport == "streamable-http":
        mcp.run("streamable-http", host=args.host, port=args.port)


if __name__ == "__main__":
    main()
