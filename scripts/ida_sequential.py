#!/usr/bin/env python3
"""通过现有 HTTP MCP 顺序切换 IDA Pro GUI 会话。"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from dataclasses import dataclass
import ctypes
from ctypes import wintypes
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
import types
from urllib.parse import urlsplit

import pywintypes
import win32api
import win32con
import win32process


DEFAULT_MCP_URL = "http://127.0.0.1:13337/mcp"
IDA_EXECUTABLES = frozenset({"ida64.exe", "ida.exe", "idaq64.exe", "idaq.exe"})
DATABASE_SUFFIXES = frozenset({".i64", ".idb"})
WM_CLOSE = 0x0010
MCP_HEALTH_TIMEOUT = 15
MCP_SAVE_TIMEOUT_CAP = 120
HEALTH_POLL_SECONDS = 1.0
CLOSE_POLL_SECONDS = 0.5
TOGGLE_POLL_ATTEMPTS = 10
TOGGLE_POLL_SECONDS = 0.1
IDA_WINDOW_CLASS = re.compile(r"^Qt\d+(?:[A-Za-z]+)?QWindowIcon$", re.IGNORECASE)


class SwitchError(RuntimeError):
    """安全切换无法继续。"""


def configure_utf8() -> None:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(encoding="utf-8", errors="replace")


def normalized_path(value: str | Path) -> str:
    path = os.path.normpath(os.path.abspath(os.fspath(value)))
    return os.path.normcase(path)


def same_path(left: str | Path, right: str | Path) -> bool:
    return normalized_path(left) == normalized_path(right)


@dataclass(frozen=True)
class McpEndpoint:
    host: str
    port: int
    path: str

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}{self.path}"


def parse_mcp_url(value: str) -> McpEndpoint:
    parts = urlsplit(value.strip())
    if parts.scheme.lower() != "http":
        raise SwitchError("--mcp-url must use http")
    if parts.username or parts.password:
        raise SwitchError("--mcp-url must not contain credentials")
    if parts.fragment:
        raise SwitchError("--mcp-url must not contain a fragment")
    if not parts.hostname:
        raise SwitchError("--mcp-url must include a host")
    if ":" in parts.hostname:
        raise SwitchError("IPv6 MCP endpoints are unsupported")
    host = parts.hostname.casefold()
    if host != "localhost":
        try:
            if not ipaddress.ip_address(host).is_loopback:
                raise SwitchError("--mcp-url host must be a loopback address")
        except ValueError as exc:
            raise SwitchError("--mcp-url host must be a loopback address") from exc
    try:
        parsed_port = parts.port
    except ValueError as exc:
        raise SwitchError(f"Invalid MCP port: {exc}") from exc
    port = 80 if parsed_port is None else parsed_port
    if port <= 0:
        raise SwitchError("Invalid MCP port: must be between 1 and 65535")
    path = parts.path or "/mcp"
    if not path.startswith("/"):
        path = f"/{path}"
    if parts.query:
        path = f"{path}?{parts.query}"
    return McpEndpoint(host, port, path)


class McpClient:
    def __init__(self, endpoint: McpEndpoint):
        self.endpoint = endpoint

    def tool(self, name: str, timeout: float = 30) -> dict:
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": name, "arguments": {}},
        }
        connection = http.client.HTTPConnection(
            self.endpoint.host, self.endpoint.port, timeout=timeout
        )
        try:
            connection.request(
                "POST",
                self.endpoint.path,
                json.dumps(payload),
                {
                    "Accept": "application/json, text/event-stream",
                    "Content-Type": "application/json",
                    "Mcp-Protocol-Version": "2025-06-18",
                },
            )
            response = connection.getresponse()
            body = response.read()
            if response.status != 200:
                preview = body[:200].decode("utf-8", errors="replace")
                raise SwitchError(f"MCP HTTP {response.status}: {preview}")
            document = json.loads(body.decode("utf-8"))
            if not isinstance(document, dict):
                raise SwitchError(f"MCP {name}: invalid response")
            if "error" in document:
                raise SwitchError(f"MCP {name}: {document['error']}")
            result = document.get("result")
            if not isinstance(result, dict):
                raise SwitchError(f"MCP {name}: missing result")
            if result.get("isError"):
                raise SwitchError(f"MCP {name}: {result.get('content')}")
            data = result.get("structuredContent")
            if not isinstance(data, dict):
                content = result.get("content")
                text = content[0].get("text") if isinstance(content, list) and content else None
                data = json.loads(text) if isinstance(text, str) else None
            if not isinstance(data, dict):
                raise SwitchError(f"MCP {name}: unexpected response shape")
            return data
        except SwitchError:
            raise
        except (OSError, http.client.HTTPException, UnicodeDecodeError, ValueError) as exc:
            raise SwitchError(f"MCP {name}: {exc}") from exc
        finally:
            connection.close()

    def health(self) -> dict:
        return self.tool("server_health", timeout=MCP_HEALTH_TIMEOUT)


def listener_pids(endpoint: McpEndpoint) -> set[int]:
    try:
        result = subprocess.run(
            ["netstat", "-ano", "-p", "TCP"],
            capture_output=True,
            check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except OSError as exc:
        raise SwitchError(f"Cannot run netstat: {exc}") from exc
    if result.returncode:
        stderr = result.stderr.decode("utf-8", errors="replace").strip()
        raise SwitchError(f"netstat failed with exit code {result.returncode}: {stderr}")
    owners: set[int] = set()
    for line in result.stdout.splitlines():
        columns = line.split()
        if not columns or columns[0].upper() != b"TCP":
            continue
        if len(columns) != 5:
            raise SwitchError(f"Malformed netstat TCP row: {line!r}")
        local, remote, _, pid = columns[1:5]
        if remote not in (b"0.0.0.0:0", b"[::]:0"):
            continue
        try:
            port = int(local.rsplit(b":", 1)[1])
            process_id = int(pid)
        except (IndexError, ValueError) as exc:
            raise SwitchError(f"Invalid netstat port or PID: {line!r}") from exc
        if not 1 <= port <= 65535 or process_id <= 0:
            raise SwitchError(f"Invalid netstat port or PID: {line!r}")
        if port == endpoint.port:
            owners.add(process_id)
    return owners


def listener_pid(endpoint: McpEndpoint) -> int | None:
    owners = listener_pids(endpoint)
    if len(owners) > 1:
        raise SwitchError(f"Ambiguous MCP port ownership: {sorted(owners)}")
    return next(iter(owners), None)


def process_exe(pid: int) -> Path | None:
    try:
        handle = win32api.OpenProcess(
            win32con.PROCESS_QUERY_LIMITED_INFORMATION, False, pid
        )
    except pywintypes.error:
        return None
    if not handle:
        return None
    try:
        return Path(win32process.GetModuleFileNameEx(handle, 0))
    except pywintypes.error:
        return None
    finally:
        win32api.CloseHandle(handle)


def is_ida_executable(path: str | Path) -> bool:
    return Path(path).name.casefold() in IDA_EXECUTABLES


def validate_ida_executable(path: str | Path) -> Path:
    executable = Path(path)
    if not executable.is_file():
        raise SwitchError(f"IDA executable missing: {executable}")
    if not is_ida_executable(executable):
        raise SwitchError(f"Not an IDA GUI executable: {executable}")
    return executable


@dataclass(frozen=True)
class WindowCandidate:
    handle: int
    title: str
    class_name: str
    visible: bool


@dataclass(frozen=True)
class AutomationDesktops:
    uia: object
    win32: object


def window_is_live_and_visible(handle: int) -> bool:
    user = ctypes.WinDLL("user32", use_last_error=True)
    user.IsWindow.argtypes = [wintypes.HWND]
    user.IsWindow.restype = wintypes.BOOL
    user.IsWindowVisible.argtypes = [wintypes.HWND]
    user.IsWindowVisible.restype = wintypes.BOOL
    return bool(user.IsWindow(handle) and user.IsWindowVisible(handle))


def is_ida_main_window(candidate: WindowCandidate) -> bool:
    return (
        candidate.visible
        and candidate.title.casefold().startswith("ida - ")
        and IDA_WINDOW_CLASS.fullmatch(candidate.class_name) is not None
    )


def select_main_window(candidates: list[WindowCandidate]) -> int:
    matches = [candidate for candidate in candidates if is_ida_main_window(candidate)]
    if len(matches) != 1:
        details = [
            (candidate.handle, candidate.title, candidate.class_name)
            for candidate in matches
        ]
        raise SwitchError(
            f"Expected one visible IDA main window, found {len(matches)}: {details}"
        )
    return matches[0].handle


def window_candidates(
    automation: AutomationDesktops,
    pid: int,
) -> list[WindowCandidate]:
    try:
        windows = automation.win32.windows(process=pid, visible_only=True)
        return [
            WindowCandidate(
                handle=int(window.handle),
                title=window.window_text(),
                class_name=window.class_name(),
                visible=bool(window.is_visible()),
            )
            for window in windows
            if window.handle
        ]
    except Exception as exc:
        raise SwitchError(f"Cannot enumerate IDA windows for PID {pid}: {exc}") from exc


def main_window(automation: AutomationDesktops, pid: int) -> int:
    return select_main_window(window_candidates(automation, pid))


def request_close(hwnd: int) -> None:
    user = ctypes.WinDLL("user32", use_last_error=True)
    user.PostMessageW.argtypes = [
        wintypes.HWND,
        wintypes.UINT,
        wintypes.WPARAM,
        wintypes.LPARAM,
    ]
    user.PostMessageW.restype = wintypes.BOOL
    if not user.PostMessageW(hwnd, WM_CLOSE, 0, 0):
        raise SwitchError("Failed to request normal IDA window close")


def label(text: str) -> str:
    return re.sub(r"\s+", " ", text.replace("&", "").replace("’", "'")).strip().casefold()


def comtypes_cache_roots() -> tuple[Path, ...]:
    roots: list[Path] = []
    local_app_data = os.environ.get("LOCALAPPDATA")
    if local_app_data:
        roots.append(Path(local_app_data) / "ida-sequential" / "comtypes")
    temporary = Path(tempfile.gettempdir()) / "ida-sequential" / "comtypes"
    if not any(same_path(temporary, root) for root in roots):
        roots.append(temporary)
    return tuple(roots)


@contextmanager
def isolated_comtypes_cache():
    previous = Path.cwd()
    errors: list[str] = []
    for cache_root in comtypes_cache_roots():
        try:
            cache_root.mkdir(parents=True, exist_ok=True)
            os.chdir(cache_root)
        except OSError as exc:
            errors.append(f"{cache_root}: {exc}")
            continue
        try:
            yield cache_root
        finally:
            os.chdir(previous)
        return
    raise SwitchError(f"Cannot create comtypes cache: {'; '.join(errors)}")


def configure_comtypes_cache(cache_root: Path) -> None:
    import comtypes

    cache_path = str(cache_root.resolve())
    module = sys.modules.get("comtypes.gen")
    if module is None:
        module = types.ModuleType("comtypes.gen")
        module.__package__ = "comtypes.gen"
        sys.modules["comtypes.gen"] = module
        comtypes.gen = module
    module.__path__ = [
        cache_path,
        *(
            path
            for path in getattr(module, "__path__", [])
            if not same_path(path, cache_path)
        ),
    ]
    client = sys.modules.get("comtypes.client")
    if client is not None:
        client.gen_dir = cache_path


def save_dialog_controls(controls) -> bool:
    entries = [
        (label(control.window_text()), getattr(control.element_info, "control_type", ""), control)
        for control in controls
    ]
    radios = [
        (text, control)
        for text, kind, control in entries
        if kind == "RadioButton" and text.startswith("pack database")
    ]
    preferred = next((control for text, control in radios if "deflate" in text), None)
    if preferred is None:
        preferred = next((control for text, control in radios if "store" in text), None)
    discards = [
        control
        for text, kind, control in entries
        if "don't save" in text and "database" in text and kind in ("CheckBox", "RadioButton")
    ]
    buttons = [
        control
        for text, kind, control in entries
        if kind == "Button" and text in ("ok", "save")
    ]
    if preferred is None or not buttons:
        return False
    try:
        if int(preferred.get_toggle_state()) != 1:
            preferred.click_input()
            for _ in range(TOGGLE_POLL_ATTEMPTS):
                time.sleep(TOGGLE_POLL_SECONDS)
                if int(preferred.get_toggle_state()) == 1:
                    break
            else:
                raise SwitchError("Pack database toggle did not become selected")
        for discard in discards:
            if discard.element_info.control_type == "CheckBox" and int(
                discard.get_toggle_state()
            ) != 0:
                discard.toggle()
                if int(discard.get_toggle_state()) != 0:
                    raise SwitchError("Cannot clear DON'T SAVE checkbox")
        for discard in discards:
            if discard.element_info.control_type == "RadioButton" and int(
                discard.get_toggle_state()
            ) != 0:
                raise SwitchError("DON'T SAVE remains selected")
        if any(
            int(control.get_toggle_state()) != 0
            for control in discards
            if control.element_info.control_type == "CheckBox"
        ):
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


def automate_save_dialog(
    automation: AutomationDesktops,
    pid: int,
    hwnd: int,
    handled: set[int],
) -> None:
    for candidate in window_candidates(automation, pid):
        handle = candidate.handle
        if handle == hwnd or handle in handled:
            continue
        if not window_is_live_and_visible(handle):
            continue
        try:
            dialog = automation.uia.window(handle=handle)
        except Exception as exc:
            if not window_is_live_and_visible(handle):
                continue
            raise SwitchError(f"Cannot attach UIA to IDA dialog {handle}: {exc}") from exc
        if not window_is_live_and_visible(handle):
            continue
        try:
            controls = dialog.descendants()
            texts = [label(control.window_text()) for control in controls]
            title = label(dialog.window_text())
        except Exception as exc:
            if not window_is_live_and_visible(handle):
                continue
            raise SwitchError(f"Cannot inspect IDA dialog safely: {exc}") from exc
        if "save database" not in title and not any(
            text.startswith("pack database") for text in texts
        ):
            continue
        if not save_dialog_controls(controls):
            raise SwitchError(
                f"IDA Save database dialog not safely recognized: {dialog.window_text()!r}"
            )
        handled.add(handle)
        print("Auto-confirmed IDA Save database (Pack database).", flush=True)


def target_for(source: Path) -> Path:
    if source.suffix.casefold() in DATABASE_SUFFIXES:
        return source
    candidates = [
        candidate
        for candidate in (
            source.with_suffix(".i64"),
            source.with_suffix(".idb"),
            Path(f"{source}.i64"),
            Path(f"{source}.idb"),
        )
        if candidate.is_file()
    ]
    unique = list(dict.fromkeys(candidates))
    if len(unique) > 1:
        raise SwitchError(f"Ambiguous existing IDBs for {source}: {unique}")
    return unique[0] if unique else source


@dataclass(frozen=True)
class IdaSession:
    pid: int
    executable: Path
    input_path: Path
    idb_path: Path
    health: dict

    def status(self, endpoint: McpEndpoint) -> dict:
        return {
            "pid": self.pid,
            "ida_path": str(self.executable),
            "mcp_url": endpoint.url,
            "server_health": self.health,
        }


def session_from_health(
    pid: int,
    executable: Path,
    health: dict,
    expected: str | Path | None = None,
    require_ready: bool = True,
) -> IdaSession:
    if health.get("status") != "ok":
        raise SwitchError(f"IDA MCP not ready: {health}")
    input_text = health.get("input_path")
    database_text = health.get("idb_path")
    if not isinstance(input_text, str) or not input_text:
        raise SwitchError(f"IDA health has no input path: {health}")
    if not isinstance(database_text, str) or not database_text:
        raise SwitchError(f"IDA health has no IDB path: {health}")
    input_path = Path(input_text)
    database_path = Path(database_text)
    if database_path.suffix.casefold() not in DATABASE_SUFFIXES:
        raise SwitchError(f"Unrecognized current IDB path: {database_path}")
    if expected is not None and not (
        same_path(input_path, expected) or same_path(database_path, expected)
    ):
        raise SwitchError(
            f"Expected {expected}, actual input={input_path}, idb={database_path}"
        )
    if require_ready and health.get("auto_analysis_ready") is not True:
        raise SwitchError("IDA auto analysis pending")
    return IdaSession(pid, executable, input_path, database_path, health)


class SystemRuntime:
    def listener_pid(self, endpoint: McpEndpoint) -> int | None:
        return listener_pid(endpoint)

    def process_exe(self, pid: int) -> Path | None:
        return process_exe(pid)

    def launch(self, executable: Path, opened: Path) -> int:
        try:
            process = subprocess.Popen(
                [str(executable), "-A", "-P+", str(opened)],
                creationflags=(
                    subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.DETACHED_PROCESS
                ),
            )
        except OSError as exc:
            raise SwitchError(f"Cannot launch IDA: {exc}") from exc
        return process.pid

    def prepare_desktop(self, pid: int):
        try:
            with isolated_comtypes_cache() as cache_root:
                configure_comtypes_cache(cache_root)
                from pywinauto import Desktop
                uia = Desktop(backend="uia")
                win32 = Desktop(backend="win32")
                uia.windows(process=pid, visible_only=True)
            return AutomationDesktops(uia, win32)
        except ImportError as exc:
            raise SwitchError(
                "Install pywinauto in the selected Python environment: "
                "python -m pip install pywinauto"
            ) from exc
        except SwitchError:
            raise
        except Exception as exc:
            raise SwitchError(f"IDA desktop automation unavailable: {exc}") from exc

    def main_window(self, automation: AutomationDesktops, pid: int) -> int:
        return main_window(automation, pid)

    def request_close(self, hwnd: int) -> None:
        request_close(hwnd)

    def monotonic(self) -> float:
        return time.monotonic()

    def sleep(self, seconds: float) -> None:
        time.sleep(seconds)


class IdaSequencer:
    def __init__(
        self,
        endpoint: McpEndpoint,
        timeout: int,
        client: McpClient | None = None,
        runtime: SystemRuntime | None = None,
    ):
        if timeout <= 0:
            raise SwitchError("--timeout must be positive")
        self.endpoint = endpoint
        self.timeout = timeout
        self.client = client or McpClient(endpoint)
        self.runtime = runtime or SystemRuntime()

    def session(
        self,
        expected: str | Path | None = None,
        require_ready: bool = True,
    ) -> IdaSession:
        pid = self.runtime.listener_pid(self.endpoint)
        if pid is None:
            raise SwitchError(f"No MCP server listening at {self.endpoint.url}")
        executable = self.runtime.process_exe(pid)
        if executable is None or not is_ida_executable(executable):
            raise SwitchError(
                f"MCP port belongs to an unexpected process: PID={pid}, "
                f"exe={executable}"
            )
        health = self.client.health()
        return session_from_health(pid, executable, health, expected, require_ready)

    def status(self) -> dict:
        return self.session(require_ready=False).status(self.endpoint)

    def open(self, source: Path, executable: Path) -> IdaSession:
        validate_ida_executable(executable)
        if not source.is_file():
            raise SwitchError(f"Sample missing: {source}")
        return self._launch(executable, source, target_for(source))

    def next(self, source: Path, expected: Path, executable: Path) -> IdaSession:
        validate_ida_executable(executable)
        if not source.is_file():
            raise SwitchError(f"Next sample missing: {source}")
        current = self.session(expected)
        if not same_path(current.executable, executable):
            raise SwitchError(
                f"--ida does not match the current process: {executable} != "
                f"{current.executable}"
            )
        opened = target_for(source)
        if any(
            same_path(opened, path) or same_path(source, path)
            for path in (current.input_path, current.idb_path)
        ):
            raise SwitchError("Next sample resolves to the current IDB")
        automation = self.runtime.prepare_desktop(current.pid)
        hwnd = self.runtime.main_window(automation, current.pid)
        print(f"Saving current IDA database: {current.idb_path}", flush=True)
        saved = self.client.tool(
            "idb_save", timeout=min(self.timeout, MCP_SAVE_TIMEOUT_CAP)
        )
        verify_save(saved, current.idb_path)
        print("MCP idb_save succeeded. Requesting normal GUI close...", flush=True)
        self.runtime.request_close(hwnd)
        self._wait_closed(current, hwnd, automation)
        print("Old IDA exited; starting the next sample.", flush=True)
        return self._launch(executable, source, opened)

    def _launch(self, executable: Path, source: Path, opened: Path) -> IdaSession:
        if self.runtime.listener_pid(self.endpoint) is not None:
            raise SwitchError(
                f"MCP port already occupied at {self.endpoint.url}; refusing a second IDA"
            )
        print(f"Opening {opened}", flush=True)
        pid = self.runtime.launch(executable, opened)
        return self._wait_ready(pid, executable, source, opened)

    def _wait_ready(
        self,
        pid: int,
        executable: Path,
        requested: Path,
        opened: Path,
    ) -> IdaSession:
        deadline = self.runtime.monotonic() + self.timeout
        reason = "MCP not available"
        while self.runtime.monotonic() < deadline:
            if self.runtime.process_exe(pid) is None:
                raise SwitchError(f"New IDA PID {pid} exited during startup")
            owner = self.runtime.listener_pid(self.endpoint)
            if owner is not None and owner != pid:
                raise SwitchError(f"MCP port owned by unexpected PID {owner}")
            if owner == pid:
                try:
                    health = self.client.health()
                    session = session_from_health(pid, executable, health)
                    if opened_matches(session, requested, opened):
                        print(
                            f"READY PID={pid} input={session.input_path} "
                            f"idb={session.idb_path}",
                            flush=True,
                        )
                        return session
                    reason = (
                        f"wrong IDA sample: input={session.input_path}, "
                        f"idb={session.idb_path}"
                    )
                except SwitchError as exc:
                    reason = str(exc)
            self.runtime.sleep(HEALTH_POLL_SECONDS)
        raise SwitchError(
            f"IDA started but not verified within {self.timeout}s "
            f"(PID={pid}): {reason}"
        )

    def _wait_closed(
        self,
        current: IdaSession,
        hwnd: int,
        automation: AutomationDesktops,
    ) -> None:
        deadline = self.runtime.monotonic() + self.timeout
        handled: set[int] = set()
        while self.runtime.monotonic() < deadline:
            complete, error = self._shutdown_state(current)
            if complete:
                return
            if error is not None:
                raise SwitchError(error)
            try:
                automate_save_dialog(automation, current.pid, hwnd, handled)
            except SwitchError as exc:
                complete, error = self._shutdown_state(current)
                if complete:
                    return
                if error is not None:
                    raise SwitchError(error) from exc
                raise
            self.runtime.sleep(CLOSE_POLL_SECONDS)
        raise SwitchError(
            "IDA did not exit normally; leaving the process running (no force-kill)"
        )

    def _shutdown_state(self, current: IdaSession) -> tuple[bool, str | None]:
        if self.runtime.process_exe(current.pid) is not None:
            return False, None
        try:
            owner = self.runtime.listener_pid(self.endpoint)
        except SwitchError as exc:
            return False, f"Cannot verify MCP port release: {exc}"
        if owner is not None:
            return False, f"IDA exited but MCP port is still owned by PID {owner}"
        try:
            database_ready = (
                current.idb_path.is_file() and current.idb_path.stat().st_size > 0
            )
        except OSError as exc:
            return False, f"Cannot verify saved IDB {current.idb_path}: {exc}"
        if not database_ready:
            return False, f"IDA exited but IDB is missing or empty: {current.idb_path}"
        return True, None


def verify_save(saved: dict, expected: str | Path) -> None:
    if saved.get("ok") is not True:
        raise SwitchError(f"idb_save failed: {saved}")
    saved_path = saved.get("path")
    if not isinstance(saved_path, str) or not same_path(saved_path, expected):
        raise SwitchError(f"idb_save returned an unexpected path: {saved_path!r}")


def opened_matches(session: IdaSession, requested: Path, opened: Path) -> bool:
    if requested.suffix.casefold() in DATABASE_SUFFIXES:
        return same_path(session.idb_path, opened)
    if opened.suffix.casefold() in DATABASE_SUFFIXES:
        return same_path(session.input_path, requested) and same_path(
            session.idb_path, opened
        )
    return same_path(session.input_path, requested)


def positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be positive")
    return parsed


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Switch IDA Pro GUI sessions through an existing HTTP MCP"
    )
    commands = parser.add_subparsers(dest="command", required=True)

    status = commands.add_parser("status", help="show the current IDA and MCP")
    status.add_argument("--mcp-url", default=DEFAULT_MCP_URL)

    opening = commands.add_parser(
        "open", help="open a first sample when the MCP port is free"
    )
    opening.add_argument("file", type=Path)
    opening.add_argument("--ida", type=Path, required=True)
    opening.add_argument("--mcp-url", default=DEFAULT_MCP_URL)
    opening.add_argument("--timeout", type=positive_int, default=180)

    following = commands.add_parser(
        "next", help="save and close the current IDA, then open the next sample"
    )
    following.add_argument("file", type=Path)
    following.add_argument("--expect-current", type=Path, required=True)
    following.add_argument("--ida", type=Path, required=True)
    following.add_argument("--mcp-url", default=DEFAULT_MCP_URL)
    following.add_argument("--timeout", type=positive_int, default=180)
    return parser


def cli(argv=None) -> int:
    configure_utf8()
    parser = build_parser()
    args = parser.parse_args(argv)
    if os.name != "nt":
        parser.error("Run in the same Windows desktop session as IDA")
    try:
        endpoint = parse_mcp_url(args.mcp_url)
        timeout = getattr(args, "timeout", 180)
        sequencer = IdaSequencer(endpoint, timeout)
        if args.command == "status":
            result = sequencer.status()
        elif args.command == "open":
            result = sequencer.open(args.file.resolve(), args.ida.resolve()).status(
                endpoint
            )
        else:
            result = sequencer.next(
                args.file.resolve(),
                args.expect_current.resolve(),
                args.ida.resolve(),
            ).status(endpoint)
        print(json.dumps(result, ensure_ascii=False, indent=2), flush=True)
    except SwitchError as exc:
        print(f"ERROR: {exc}", file=sys.stderr, flush=True)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(cli())
