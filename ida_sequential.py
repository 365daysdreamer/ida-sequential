#!/usr/bin/env python3
"""Switch IDA Pro GUI samples sequentially through an existing HTTP MCP endpoint.

Windows desktop only. Save via current ida-pro-mcp idb_save, close normally,
handle the native Save database dialog if shown, then reopen a single IDA GUI
on the same port.
"""
from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes
import http.client
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import time

HOST, PORT = "127.0.0.1", 13337
IDA_EXES = {"ida64.exe", "ida.exe", "idaq64.exe", "idaq.exe"}


class SwitchError(RuntimeError):
    pass


def same_path(a: str | Path, b: str | Path) -> bool:
    return os.path.normcase(os.path.abspath(str(a))) == os.path.normcase(os.path.abspath(str(b)))


def rpc_tool(name: str, timeout: float = 30) -> dict:
    """Call the GUI plugin's JSON-response MCP endpoint (without a second MCP)."""
    payload = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": name, "arguments": {}}}
    conn = http.client.HTTPConnection(HOST, PORT, timeout=timeout)
    try:
        conn.request("POST", "/mcp", json.dumps(payload), {
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
            "Mcp-Protocol-Version": "2025-06-18",
        })
        response = conn.getresponse()
        body = response.read()
        if response.status != 200:
            raise SwitchError(f"MCP HTTP {response.status}: {body[:200]!r}")
        result = json.loads(body)
        if "error" in result:
            raise SwitchError(f"MCP {name}: {result['error']}")
        output = result["result"]
        if output.get("isError"):
            raise SwitchError(f"MCP {name}: {output.get('content')}")
        data = output.get("structuredContent")
        if not isinstance(data, dict):
            data = json.loads(output["content"][0]["text"])
        if not isinstance(data, dict):
            raise SwitchError(f"MCP {name}: unexpected response shape")
        return data
    except (OSError, ValueError, KeyError, IndexError, TypeError) as exc:
        raise SwitchError(f"MCP {name}: {exc}") from exc
    finally:
        conn.close()


def health() -> dict:
    info = rpc_tool("server_health", timeout=15)
    if info.get("status") != "ok":
        raise SwitchError(f"IDA MCP not ready: {info}")
    return info


class TcpRow(ctypes.Structure):
    _fields_ = [(field, ctypes.c_uint32) for field in (
        "state", "local_addr", "local_port", "remote_addr", "remote_port", "pid"
    )]


def listener_pid() -> int | None:
    """Get the owning PID through Windows IP Helper API (locale independent)."""
    api = ctypes.WinDLL("iphlpapi", use_last_error=True)
    query = api.GetExtendedTcpTable
    query.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32), wintypes.BOOL,
                      ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32]
    query.restype = ctypes.c_uint32
    size = ctypes.c_uint32(0)
    status = query(None, ctypes.byref(size), False, socket.AF_INET, 3, 0)  # OWNER_PID_LISTENER
    if status != 122:  # ERROR_INSUFFICIENT_BUFFER
        raise SwitchError(f"GetExtendedTcpTable size query failed: {status}")
    buffer = ctypes.create_string_buffer(size.value)
    status = query(buffer, ctypes.byref(size), False, socket.AF_INET, 3, 0)
    if status:
        raise SwitchError(f"GetExtendedTcpTable failed: {status}")
    count = ctypes.c_uint32.from_buffer(buffer).value
    if 4 + count * ctypes.sizeof(TcpRow) > size.value:
        raise SwitchError("TCP listener table returned an invalid size")
    base = ctypes.addressof(buffer) + ctypes.sizeof(ctypes.c_uint32)
    pids = set()
    for i in range(count):
        row = TcpRow.from_address(base + i * ctypes.sizeof(TcpRow))
        addr = socket.inet_ntoa(row.local_addr.to_bytes(4, "little"))
        port = socket.ntohs(row.local_port & 0xffff)
        if row.state == 2 and port == PORT and addr in (HOST, "0.0.0.0"):
            pids.add(row.pid)
    if len(pids) > 1:
        raise SwitchError(f"Ambiguous TCP port ownership: {pids}")
    return next(iter(pids), None)


def kernel32():
    k = ctypes.WinDLL("kernel32", use_last_error=True)
    k.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    k.OpenProcess.restype = wintypes.HANDLE
    k.CloseHandle.argtypes = [wintypes.HANDLE]
    k.CloseHandle.restype = wintypes.BOOL
    k.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    k.GetExitCodeProcess.restype = wintypes.BOOL
    k.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
    k.QueryFullProcessImageNameW.restype = wintypes.BOOL
    return k


def process_exe(pid: int) -> str | None:
    k = kernel32()
    handle = k.OpenProcess(0x1000, False, pid)
    if not handle:
        return None
    try:
        code = wintypes.DWORD()
        if not k.GetExitCodeProcess(handle, ctypes.byref(code)):
            raise SwitchError(f"Cannot query process {pid}")
        if code.value != 259:  # STILL_ACTIVE
            return None
        buf = ctypes.create_unicode_buffer(32768)
        size = wintypes.DWORD(len(buf))
        if not k.QueryFullProcessImageNameW(handle, 0, buf, ctypes.byref(size)):
            raise SwitchError(f"Cannot query executable for PID {pid}")
        return buf.value
    finally:
        k.CloseHandle(handle)


def connected_ida() -> tuple[int, Path, dict]:
    pid = listener_pid()
    if pid is None:
        raise SwitchError(f"No MCP server listening on {HOST}:{PORT}")
    exe = process_exe(pid)
    if not exe or Path(exe).name.lower() not in IDA_EXES:
        raise SwitchError(f"TCP {PORT} belongs to an unexpected process: PID={pid}, exe={exe}")
    return pid, Path(exe), health()


def main_window(pid: int) -> int:
    user = ctypes.WinDLL("user32", use_last_error=True)
    cb_type = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    user.EnumWindows.argtypes = [cb_type, wintypes.LPARAM]
    user.EnumWindows.restype = wintypes.BOOL
    user.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
    user.GetWindowThreadProcessId.restype = wintypes.DWORD
    user.GetWindow.argtypes = [wintypes.HWND, wintypes.UINT]
    user.GetWindow.restype = wintypes.HWND
    user.GetWindowTextLengthW.argtypes = [wintypes.HWND]
    user.GetWindowTextLengthW.restype = ctypes.c_int
    user.GetWindowTextW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
    user.GetWindowTextW.restype = ctypes.c_int
    matches = []

    @cb_type
    def collect(hwnd, unused):
        owner = wintypes.DWORD()
        user.GetWindowThreadProcessId(hwnd, ctypes.byref(owner))
        if owner.value == pid and not user.GetWindow(hwnd, 4):  # GW_OWNER
            length = user.GetWindowTextLengthW(hwnd)
            title = ctypes.create_unicode_buffer(length + 1)
            user.GetWindowTextW(hwnd, title, len(title))
            if "IDA" in title.value.upper():
                matches.append((int(hwnd), title.value))
        return True

    if not user.EnumWindows(collect, 0) or len(matches) != 1:
        raise SwitchError(f"Expected one IDA main window for PID {pid}, found {matches}")
    return matches[0][0]


def close_window(hwnd: int):
    user = ctypes.WinDLL("user32", use_last_error=True)
    user.PostMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
    user.PostMessageW.restype = wintypes.BOOL
    if not user.PostMessageW(hwnd, 0x0010, 0, 0):  # WM_CLOSE
        raise SwitchError("Failed to request normal IDA window close")


def label(text: str) -> str:
    return re.sub(r"\s+", " ", text.replace("&", "").replace("’", "'")).strip().casefold()


def save_dialog_controls(controls) -> bool:
    """Confirm only a recognized IDA save dialog; never accept discard."""
    entries = [(label(c.window_text()), getattr(c.element_info, "control_type", ""), c) for c in controls]
    radios = [(text, c) for text, kind, c in entries if kind == "RadioButton" and text.startswith("pack database")]
    preferred = next((c for text, c in radios if "deflate" in text), None)
    if preferred is None:
        preferred = next((c for text, c in radios if "store" in text), None)
    discards = [c for text, kind, c in entries if "don't save" in text and "database" in text and kind in ("CheckBox", "RadioButton")]
    buttons = [c for text, kind, c in entries if kind == "Button" and text in ("ok", "save")]
    if preferred is None or not buttons:
        return False
    try:
        for discard in discards:
            if discard.element_info.control_type == "CheckBox" and discard.get_toggle_state() != 0:
                discard.toggle()
                if discard.get_toggle_state() != 0:
                    raise SwitchError("Cannot clear DON'T SAVE checkbox")
        if not preferred.is_selected():
            try:
                preferred.select()
            except Exception:
                preferred.click_input()
        if not preferred.is_selected():
            raise SwitchError("Cannot select Pack database")
        for discard in discards:
            if discard.element_info.control_type == "RadioButton" and discard.is_selected():
                raise SwitchError("DON'T SAVE remains selected")
        if any(c.get_toggle_state() != 0 for c in discards if c.element_info.control_type == "CheckBox"):
            raise SwitchError("DON'T SAVE became checked")
        try:
            buttons[0].click()
        except Exception:
            buttons[0].click_input()
        return True
    except SwitchError:
        raise
    except Exception as exc:
        raise SwitchError(f"IDA save dialog controls inaccessible: {exc}") from exc


def automate_save_dialog(desktop, pid: int, hwnd: int, handled: set[int]):
    for dialog in desktop.windows(process=pid, visible_only=True):
        handle = getattr(dialog, "handle", None)
        if not handle or handle == hwnd or handle in handled:
            continue
        try:
            controls = dialog.descendants()
            texts = [label(c.window_text()) for c in controls]
            title = label(dialog.window_text())
        except Exception as exc:
            raise SwitchError(f"Cannot inspect IDA dialog safely: {exc}") from exc
        if "save database" not in title and not any(t.startswith("pack database") for t in texts):
            continue
        if not save_dialog_controls(controls):
            raise SwitchError(f"IDA Save database dialog not safely recognized: {dialog.window_text()!r}")
        handled.add(handle)
        print("Auto-confirmed IDA Save database (Pack database).", flush=True)


def wait_closed(pid: int, hwnd: int, db: Path, timeout: int, desktop):
    deadline = time.monotonic() + timeout
    handled: set[int] = set()
    while time.monotonic() < deadline:
        if process_exe(pid) is None:
            # A different process must not take over the same listener unnoticed.
            owner = listener_pid()
            if owner is not None:
                raise SwitchError(f"IDA exited but TCP {PORT} is still owned by PID {owner}")
            if not db.is_file() or db.stat().st_size == 0:
                raise SwitchError(f"IDA exited but IDB is missing/empty: {db}")
            return
        automate_save_dialog(desktop, pid, hwnd, handled)
        time.sleep(0.5)
    raise SwitchError("IDA did not exit normally; leaving the process running (no force-kill)")


def target_for(source: Path) -> Path:
    if source.suffix.lower() in (".i64", ".idb"):
        return source
    candidates = [source.with_suffix(ext) for ext in (".i64", ".idb")
                  if source.with_suffix(ext).is_file()]
    if len(candidates) > 1:
        raise SwitchError(f"Ambiguous existing IDBs for {source}: {candidates}")
    return candidates[0] if candidates else source


def wait_ready(pid: int, requested: Path, opened: Path, timeout: int):
    deadline = time.monotonic() + timeout
    reason = "MCP not available"
    while time.monotonic() < deadline:
        if process_exe(pid) is None:
            raise SwitchError(f"New IDA PID {pid} exited during startup")
        try:
            owner = listener_pid()
            if owner is not None and owner != pid:
                raise SwitchError(f"MCP port {PORT} owned by unexpected PID {owner}")
            if owner == pid:
                info = health()
                db_path = info.get("idb_path")
                input_path = info.get("input_path")
                if opened.suffix.lower() in (".i64", ".idb"):
                    matched = bool(db_path and same_path(db_path, opened))
                    if matched and requested.suffix.lower() not in (".i64", ".idb") and input_path:
                        matched = same_path(input_path, requested)
                else:
                    matched = bool(input_path and same_path(input_path, requested))
                if not matched:
                    reason = f"wrong IDA sample: input={input_path!r}, idb={db_path!r}"
                elif info.get("auto_analysis_ready") is not True:
                    reason = "IDA auto analysis pending"
                else:
                    print(f"READY PID={pid} input={input_path} idb={db_path}", flush=True)
                    return
        except SwitchError as exc:
            reason = str(exc)
        time.sleep(1)
    raise SwitchError(f"IDA started but not verified within {timeout}s (PID={pid}): {reason}")


def start(exe: Path, source: Path, timeout: int):
    if not exe.is_file() or exe.name.lower() not in IDA_EXES:
        raise SwitchError(f"Not an IDA GUI executable: {exe}")
    if not source.is_file():
        raise SwitchError(f"Sample missing: {source}")
    if listener_pid() is not None:
        raise SwitchError(f"TCP {PORT} already occupied; not starting another IDA")
    opened = target_for(source)
    print(f"Opening {opened}", flush=True)
    # IDA 8.3-compatible GUI switches (both documented before IDA 8.3):
    # -A: accept default loading prompts; -P+: compress the saved database.
    # Do not use -B: its analysis.idc can exit before the GUI MCP plugin starts.
    try:
        proc = subprocess.Popen([str(exe), "-A", "-P+", str(opened)],
                                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.DETACHED_PROCESS)
    except OSError as exc:
        raise SwitchError(f"Cannot launch IDA: {exc}") from exc
    wait_ready(proc.pid, source, opened, timeout)


def switch(source: Path, expected: Path, timeout: int):
    if not source.is_file():
        raise SwitchError(f"Next sample missing: {source}")
    pid, exe, info = connected_ida()
    current = info.get("input_path")
    db = info.get("idb_path")
    if not ((current and same_path(current, expected)) or (db and same_path(db, expected))):
        raise SwitchError(f"Expected {expected}, actual input={current!r}, idb={db!r}")
    if not db or Path(db).suffix.lower() not in (".i64", ".idb"):
        raise SwitchError(f"Unrecognized current IDB path: {db!r}")
    if (current and same_path(source, current)) or same_path(source, db) or same_path(target_for(source), db):
        raise SwitchError("Next sample resolves to the current IDB")
    try:
        from pywinauto import Desktop
        desktop = Desktop(backend="uia")
        desktop.windows(process=pid, visible_only=True)  # fail before touching IDB
    except ImportError as exc:
        raise SwitchError("Install pywinauto first: python -m pip install pywinauto") from exc
    except Exception as exc:
        raise SwitchError(f"IDA desktop automation unavailable: {exc}") from exc
    hwnd = main_window(pid)
    print(f"Saving current IDA database: {db}", flush=True)
    result = rpc_tool("idb_save", timeout=min(timeout, 120))
    if result.get("ok") is not True or (result.get("path") and not same_path(result["path"], db)):
        raise SwitchError(f"idb_save failed or returned a different path: {result}")
    print("MCP idb_save succeeded. Requesting normal GUI close...", flush=True)
    close_window(hwnd)
    wait_closed(pid, hwnd, Path(db), timeout, desktop)
    print("Old IDA exited; starting next sample.", flush=True)
    start(exe, source, timeout)


def cli(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Switch IDA GUI samples through existing MCP :13337")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("status")
    op = commands.add_parser("open", help="open a first sample when no IDA MCP is running")
    op.add_argument("file", type=Path)
    op.add_argument("--ida", type=Path, required=True, help="path to ida64.exe")
    nx = commands.add_parser("next", help="save, close and open the next sample")
    nx.add_argument("file", type=Path)
    nx.add_argument("--expect-current", type=Path, required=True)
    for p in (op, nx):
        p.add_argument("--timeout", type=int, default=180)
    args = parser.parse_args(argv)
    if os.name != "nt":
        parser.error("Run in the same Windows desktop session as IDA")
    try:
        if args.command == "status":
            pid, exe, info = connected_ida()
            print(json.dumps({"pid": pid, "exe": str(exe), "mcp": f"http://{HOST}:{PORT}/mcp", "health": info}, ensure_ascii=False, indent=2))
        elif args.command == "open":
            if args.timeout <= 0:
                raise SwitchError("--timeout must be positive")
            start(args.ida.resolve(), args.file.resolve(), args.timeout)
        else:
            if args.timeout <= 0:
                raise SwitchError("--timeout must be positive")
            switch(args.file.resolve(), args.expect_current.resolve(), args.timeout)
    except SwitchError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(cli())
