---
name: ida-sequential
description: Switch files serially in one local IDA Pro 8.3 GUI session through ida-pro-mcp by saving, closing, reopening, and validating each expected file before analysis continues.
---

# IDA Sequential

## Confirm interpreter

When the local `ida-pro-mcp` endpoint provides `py_eval`, run read-only code to derive the standalone interpreter:

```python
import sys
from pathlib import Path

Path(sys.base_prefix) / "python.exe"
```

Set the confirmed values, then verify the Python environment:

```powershell
$Python = "<PYTHON_EXE>"
$Ida = "<IDA_EXE>"
$McpUrl = "<MCP_URL>"
Test-Path -LiteralPath $Python -PathType Leaf
& $Python -c "import pywinauto, win32api"
```

If MCP or `py_eval` is unavailable, or the derived file is missing or unusable, request `<PYTHON_EXE>` from the user. Use `py_eval` only with a trusted local loopback endpoint.

## Execution cycle

Use a loopback `$McpUrl`; the CLI rejects other hosts.

```powershell
& $Python ida_sequential.py status --mcp-url $McpUrl
```

Open the first file when the MCP port is free:

```powershell
& $Python ida_sequential.py open "<SAMPLE>" --ida $Ida --mcp-url $McpUrl --timeout 600
```

Analyze one file using relevant skills if exist, and save the report. Then switch and verify the next session:

```powershell
& $Python ida_sequential.py next "<NEXT_SAMPLE>" --expect-current "<CURRENT_SAMPLE>" --ida $Ida --mcp-url $McpUrl --timeout 600
```

The switch saves the current IDB, closes the GUI normally, waits for the old PID and port to clear, launches the next file, and checks its PID and identity.

Require exit code `0`. Confirm from `status` or `server_health`:

- `status` is `ok`
- `input_path` matches the expected file
- `idb_path` belongs to that file
- `auto_analysis_ready` is `true`

## Stop conditions

Handle one file at a time with one IDA GUI process and one MCP listener. Stop for a nonzero exit, identity mismatch, save failure, unresolved save dialog, port conflict, abnormal close, or failed startup verification.

On failure, keep the IDA process, IDB, and error output for inspection. Retry only after `status` and the visible window confirm a safe state.
