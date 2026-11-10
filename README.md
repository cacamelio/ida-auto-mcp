# ida-auto-mcp

An MCP server that gives AI coding assistants (OpenCode, Claude Desktop, Cursor, Antigravity) control over the IDA Pro lifecycle so they can analyze multiple binaries without manual intervention.

---

### The Problem

If you use [ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp), the MCP server runs embedded inside the IDA Pro process (listening on `127.0.0.1:13337`). 

Because IDA is strictly one database per process, unattended multi-binary analysis wasn't possible:
1. You open `binaryA.dll` in IDA.
2. The AI inspects functions, decompiles, and finishes analyzing `binaryA.dll`.
3. The AI wants to look at `binaryB.dll` next, but can't: IDA is locked to `binaryA.dll`.
4. You have to sit at your desk, save the database, kill IDA, open `binaryB.dll`, wait for auto-analysis to finish, make sure port 13337 binds, and resume prompting.

### The Solution

`ida-auto-mcp` runs as a standalone local MCP server alongside your existing `ida-pro-mcp` setup. It exposes process control tools (`ida_open`, `ida_switch`, `ida_close`, `ida_save`, `ida_status`) so your AI assistant can drive batch analysis pipelines on its own:

```text
[ AI Assistant (OpenCode / Claude / Cursor) ]
      │                                │
      │ (Process Control via stdio)    │ (Static Analysis via HTTP/SSE)
      ▼                                ▼
[ ida-auto-mcp ]                [ ida-pro-mcp (port 13337) ]
      │                                ▲
      │ spawns / saves / terminates    │ hosted inside
      ▼                                │
[ IDA Pro 9.x (ida64.exe -A) ] ────────┘
```

When switching binaries, `ida-auto-mcp`:
1. Triggers an `idb_save` RPC call to IDA so you don't lose any decompilation or typing work.
2. Sends a clean close signal and waits for the process and TCP port 13337 to be released.
3. Launches the next binary with `-A` (autonomous mode, so no interactive prompts block execution).
4. Polls IDA until auto-analysis completes (`auto_is_ok()`) and the MCP server is ready before returning to the AI.

---

## Installation

Requires Python 3.11+ and IDA Pro 9.x (Windows).

```bash
git clone https://github.com/cacamelio/ida-auto-mcp.git
cd ida-auto-mcp
pip install -r requirements.txt
```

### Auto-Config

Run the setup helper to automatically register the server in your installed clients:

```bash
python setup_clients.py
```

Or configure manually below.

---

## Client Configuration

### OpenCode (`~/.config/opencode/opencode.json`)

Add `ida-auto` under the `"mcp"` key:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "ida-pro": {
      "type": "remote",
      "url": "http://127.0.0.1:13337/sse",
      "enabled": true
    },
    "ida-auto": {
      "type": "local",
      "command": [
        "python",
        "C:\\path\\to\\ida-auto-mcp\\server.py"
      ],
      "enabled": true
    }
  }
}
```

### Claude Desktop (`claude_desktop_config.json`)

```json
{
  "mcpServers": {
    "ida-auto": {
      "command": "python",
      "args": [
        "C:\\path\\to\\ida-auto-mcp\\server.py"
      ]
    }
  }
}
```

### Antigravity (`~/.gemini/config/mcp_config.json`)

```json
{
  "mcpServers": {
    "ida-pro-mcp": {
      "type": "http",
      "serverUrl": "http://127.0.0.1:13337/mcp"
    },
    "ida-auto": {
      "command": "python",
      "args": [
        "C:\\path\\to\\ida-auto-mcp\\server.py"
      ]
    }
  }
}
```

### Cursor (`~/.cursor/mcp.json`)

```json
{
  "mcpServers": {
    "ida-auto": {
      "command": "python",
      "args": [
        "C:\\path\\to\\ida-auto-mcp\\server.py"
      ]
    }
  }
}
```

---

## Available Tools

### `ida_open`
Opens a target file in IDA. If another instance is running, it saves and closes it first.
- `target_path` (str, required): Path to the `.dll`, `.exe`, `.so`, or `.i64`.
- `gui` (bool, default: `True`): Launches `ida64.exe` (GUI) or `idat64.exe` (headless text mode).
- `autonomous` (bool, default: `True`): Passes `-A` to silence all interactive popups/dialogs.
- `wait_ready` (bool, default: `True`): Blocks until auto-analysis completes.
- `timeout_sec` (int, default: `180`): Max wait time for analysis.
- `force_new_database` (bool, default: `False`): Ignores existing `.i64` and starts fresh.

### `ida_switch`
Atomic switch between binaries. Flushes the active database, closes IDA, frees port 13337, spawns the next target, and waits for analysis.
- Takes the same arguments as `ida_open`.

### `ida_close`
Flushes the `.i64` database and shuts down the active IDA instance.
- `save` (bool, default: `True`): Writes database to disk before closing.
- `timeout_sec` (int, default: `15`).

### `ida_status`
Queries IDA's `server_health` endpoint and reports loaded module, IDB path, PID, and whether auto-analysis has completed.

### `ida_save`
Flushes current disassembly and decompilation changes to the `.i64` database without closing IDA.

### `ida_list_targets`
Scans a folder for candidate binaries (`.dll`, `.exe`, `.sys`, etc.) and indicates whether an `.i64` database is already present for each file.
- `directory` (str, required).
- `extensions` (list[str], default: `[".dll", ".exe", ".sys", ".so", ".bin"]`).
- `recursive` (bool, default: `False`).

---

## Example Prompt

Once configured, you can give your AI prompts like:

> "Look inside `D:\programs\my_program\`. Use `ida_list_targets` to see what DLLs are there, then open `test.dll` and `test1.dll` sequentially. For each one, summarize its exported interfaces and string references, then close IDA when done."

The AI will handle opening, analyzing, saving, and switching targets completely on its own.

---

## Details & Edge Cases

- **Autonomous Mode (`-A`)**: By default, `ida-auto-mcp` passes `-A` so IDA won't halt on prompt dialogs (like PDB download confirmations or compiler signature choices).
- **Existing Databases & Binary Updates**: If a `.i64` or `.idb` file exists, `ida-auto-mcp` checks binary fingerprints (file size, high-resolution modification timestamp, and SHA-256 content hash). If the binary hasn't changed, it reuses the database for instant loading. If the binary was updated on disk after the database was saved, `ida-auto-mcp` automatically archives the database and any loose working files (`.id0`, `.id1`, etc.) to a verified backup in `ida_backups` with metadata sidecars before generating a fresh database.
- **Automatic 14-Day Backup Retention**: Automatically generated database backups older than 14 days (14 × 24 hours) are cleanly pruned. Original binaries, primary databases, loose recovery files, active files, and foreign files are strictly protected and never deleted.
- **Process Ownership & Port Conflict Handling**: When multiple IDA instances run or when instances restart, `ida-auto-mcp` uses exact process creation time and verified executable checks to prevent PID reuse issues, waits for ports to release from `TIME_WAIT`, and targets each IDA instance by its actual registered port rather than assuming port 13337.
- **Cross-Process Synchronization**: Uses in-process reentrant locking paired with an OS-level Windows Named Mutex to ensure target switching and save operations are strictly serialized without races or deadlocks.

---

## License

MIT
