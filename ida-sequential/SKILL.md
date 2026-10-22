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

{
    "python_home": str(Path(sys.base_prefix) / "python.exe"),
    "python_version": sys.version,
}
```

If MCP or `py_eval` is unavailable, or the derived file is missing or unusable, request `<PYTHON_EXE>` from the user.

Verify the Python environment provided above:

```powershell
$Python = "<PYTHON_EXE>"
Test-Path -LiteralPath $Python -PathType Leaf
& $Python -c "import pywinauto, win32api; print('dependencies ready')"
```

If dependency is missing, request approval from the user and run:

```powershell
& $Python -m pip install pywinauto
```

## Variables

```powershell
$Ida = "<PATH/TO/IDA_EXE>"
$McpUrl = "<MCP_URL>" # default="http://127.0.0.1:13337/mcp"
$Timeout = <seconds> # default=180
```

## Arguments

- `--expect-current` verifies current sample or IDB identity.
- `--ida` points to the executable of IDA GUI.
- `--mcp-url` points to the streamable MCP server address. Use a loopback address; the CLI rejects other hosts.
- `--timeout` controls the waiting time (in seconds) for open/close.

## Commands

`status`: Show the current IDA and MCP.
- Optional argument:
  - `--mcp-url $McpUrl`

`open`: Open a sample when the MCP port is free.
- Required argument:
  - `"<PATH/TO/SAMPLE>"`
  - `--ida $Ida`
- Optional arguments:
  - `--mcp-url $McpUrl`
  - `--timeout $Timeout`

`next`: Save and close the current IDA, then open the next sample.
- Required argument:
  - `"<PATH/TO/NEXT_SAMPLE>"`
  - `--expect-current "<PATH/TO/CURRENT_SAMPLE>"`
- Optional arguments:
  - `--ida $Ida` for different executables for the next sample
  - `--mcp-url $McpUrl`
  - `--timeout $Timeout`

## Usage

`status`:
```powershell
& $Python ida_sequential.py status
```

`open`:
```powershell
& $Python ida_sequential.py open "<PATH/TO/SAMPLE>" --ida $Ida
```

`next`:
```powershell
& $Python ida_sequential.py next "<PATH/TO/NEXT_SAMPLE>" --expect-current "<PATH/TO/CURRENT_SAMPLE>"
```

## Execution cycle

Handle one file at a time with one IDA GUI process and one MCP listener:

```text
Open the first file when the MCP port is free -> Analyze the file using relevant skills if exist -> Save and close the current IDA, then switch and verify the next session

Or

Analyze the current file using relevant skills if exist -> Save and close the current IDA, then switch and verify the next session
```

The switch saves the current IDB, closes the GUI normally, waits for the old PID and port to clear, launches the next file, and checks its PID and identity.

## Verify

Require exit code `0`. Confirm from `status`:
- `server_health.status` is `ok`
- `input_path` matches the expected file
- `idb_path` belongs to that file
- `auto_analysis_ready` is `true`

## Stop conditions

Stop the current turn for a nonzero exit, identity mismatch, save failure, unresolved save dialog, port conflict, abnormal close, or failed startup verification.

On failure, keep the IDA process, IDB, and error output for inspection. Retry only after `status` and the visible window confirm a safe state.
