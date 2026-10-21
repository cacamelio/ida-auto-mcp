"""IDA Auto MCP Server

An MCP server designed for OpenCode, Claude Desktop, Cursor, and Antigravity
to autonomously orchestrate IDA Pro instances, switch between binaries/databases,
wait for auto-analysis, and cleanly save/close databases.
"""

from __future__ import annotations

import argparse
import logging
from typing import Any, Dict, List, Optional

from mcp.server.mcpserver import MCPServer

from ida_controller import (
    close_active_target,
    get_current_status,
    list_candidate_binaries,
    open_target,
    save_active_idb,
)

logger = logging.getLogger("ida_auto_mcp")

mcp = MCPServer(
    name="ida-auto-mcp",
    version="1.0.0",
    description="Automate opening, closing, and switching binaries in IDA Pro for unattended static analysis.",
)


@mcp.tool()
def ida_open(
    target_path: str,
    gui: bool = True,
    autonomous: bool = True,
    wait_ready: bool = True,
    timeout_sec: int = 180,
    force_new_database: bool = False,
) -> Dict[str, Any]:
    """Open a binary or database in IDA Pro and wait for auto-analysis and MCP readiness.

    If an IDA instance is already open, its database is automatically saved and closed first.
    Once this tool returns successfully, the target is fully loaded and ready for static analysis
    using the standard IDA MCP tools (decompile, list_funcs, survey_binary, etc.).

    Args:
        target_path: Absolute or relative path to the binary (.dll, .exe, .so, etc.) or existing IDB (.i64).
        gui: If True (default), launches ida64.exe. If False, launches headless idat64.exe.
        autonomous: If True (default), passes -A to suppress interactive popups and modal dialogs.
        wait_ready: If True (default), waits until IDA auto-analysis finishes and the MCP server is responsive.
        timeout_sec: Maximum seconds to wait for IDA auto-analysis and MCP initialization (default 180).
        force_new_database: If True, forces creating a new database even if an existing .i64 is present.
    """
    return open_target(
        target_path=target_path,
        gui=gui,
        autonomous=autonomous,
        wait_ready=wait_ready,
        timeout_sec=float(timeout_sec),
        force_new_database=force_new_database,
    )


@mcp.tool()
def ida_close(save: bool = True, timeout_sec: int = 15) -> Dict[str, Any]:
    """Gracefully save the database and close the currently running IDA Pro instance.

    Args:
        save: If True (default), triggers database save (.i64/.idb) before closing.
        timeout_sec: Maximum seconds to wait for process termination and port release.
    """
    return close_active_target(save=save, timeout_sec=float(timeout_sec))


@mcp.tool()
def ida_switch(
    target_path: str,
    gui: bool = True,
    autonomous: bool = True,
    wait_ready: bool = True,
    timeout_sec: int = 180,
    force_new_database: bool = False,
) -> Dict[str, Any]:
    """Switch to a different target: automatically saves the current IDA database, closes it,
    and opens the new binary.

    Args:
        target_path: Path to the next binary or database to open.
        gui: If True (default), runs GUI mode.
        autonomous: If True (default), passes -A for unattended automation.
        wait_ready: If True (default), waits until auto-analysis completes.
        timeout_sec: Maximum seconds to wait.
        force_new_database: If True, ignores existing .i64 database.
    """
    return open_target(
        target_path=target_path,
        gui=gui,
        autonomous=autonomous,
        wait_ready=wait_ready,
        timeout_sec=float(timeout_sec),
        force_new_database=force_new_database,
    )


@mcp.tool()
def ida_status() -> Dict[str, Any]:
    """Check the status of IDA Pro, the active target binary, auto-analysis progress, and MCP server health."""
    return get_current_status()


@mcp.tool()
def ida_save() -> Dict[str, Any]:
    """Save the currently open IDA database (.i64/.idb) to disk without closing IDA."""
    return save_active_idb()


@mcp.tool()
def ida_list_targets(
    directory: str,
    extensions: Optional[List[str]] = None,
    recursive: bool = False,
) -> Dict[str, Any]:
    """Scan a folder for candidate binary files (e.g. .dll, .exe) to analyze in IDA.

    Shows file sizes and whether an existing .i64 database is already present for each file.

    Args:
        directory: Path to the folder containing targets.
        extensions: List of extensions to include (default: [".dll", ".exe", ".sys", ".so", ".bin"]).
        recursive: If True, recursively scans subdirectories.
    """
    return list_candidate_binaries(
        directory=directory,
        extensions=extensions,
        recursive=recursive,
    )


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

    if args.transport == "stdio":
        mcp.run("stdio")
    elif args.transport == "sse":
        mcp.run("sse", host=args.host, port=args.port)
    elif args.transport == "streamable-http":
        mcp.run("streamable-http", host=args.host, port=args.port)


if __name__ == "__main__":
    main()
