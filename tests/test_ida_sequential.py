from __future__ import annotations

from contextlib import redirect_stderr
import importlib.util
from io import StringIO
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch


ROOT = Path(__file__).resolve().parents[1]
SKILL_DIR = ROOT / "ida-sequential"
if str(SKILL_DIR) not in sys.path:
    sys.path.insert(0, str(SKILL_DIR))

import ida_sequential as target


class FakeDesktop:
    def __init__(self):
        self.uia = self
        self.win32 = self

    def windows(self, process: int, visible_only: bool):
        return []


class FakeRuntime:
    def __init__(self, executable: Path, current_pid: int = 100, new_pid: int = 200):
        self.executable = executable
        self.current_pid = current_pid
        self.new_pid = new_pid
        self.owner = current_pid
        self.closed = False
        self.launched = False
        self.open_path = None
        self.launch_executable = None
        self.events: list[str] = []
        self.clock_values = None

    def listener_pid(self, endpoint):
        return self.owner

    def process_exe(self, pid: int):
        if pid == self.current_pid and not self.closed:
            return self.executable
        if pid == self.new_pid and self.launched:
            return self.executable
        return None

    def launch(self, executable: Path, opened: Path):
        self.events.append("launch")
        self.launched = True
        self.owner = self.new_pid
        self.open_path = opened
        self.launch_executable = executable
        return self.new_pid

    def prepare_desktop(self, pid: int):
        self.events.append("prepare")
        return FakeDesktop()

    def main_window(self, automation, pid: int):
        return 101

    def request_close(self, hwnd: int):
        self.events.append("close")
        self.closed = True
        self.owner = None

    def monotonic(self):
        if self.clock_values is not None:
            return next(self.clock_values)
        return 0.0

    def sleep(self, seconds: float):
        self.events.append("sleep")


class McpUrlTests(unittest.TestCase):
    def test_parses_custom_endpoint(self):
        endpoint = target.parse_mcp_url("http://localhost:14000/custom/mcp?mode=json")

        self.assertEqual(endpoint.host, "localhost")
        self.assertEqual(endpoint.port, 14000)
        self.assertEqual(endpoint.path, "/custom/mcp?mode=json")
        self.assertEqual(
            endpoint.url, "http://localhost:14000/custom/mcp?mode=json"
        )

    def test_uses_default_path(self):
        endpoint = target.parse_mcp_url("http://127.0.0.1:13337")

        self.assertEqual(endpoint.path, "/mcp")

    def test_rejects_invalid_endpoints(self):
        invalid = (
            "https://127.0.0.1:13337/mcp",
            "http:///mcp",
            "http://[::1]:13337/mcp",
            "http://127.0.0.1:0/mcp",
            "http://127.0.0.1:not-a-port/mcp",
            "http://user:pass@127.0.0.1:13337/mcp",
            "http://127.0.0.1:13337/mcp#fragment",
        )
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(target.SwitchError):
                target.parse_mcp_url(value)

    def test_rejects_non_loopback_host(self):
        with self.assertRaisesRegex(target.SwitchError, "loopback"):
            target.parse_mcp_url("http://192.0.2.10:13337/mcp")


class ComtypesCacheTests(unittest.TestCase):
    def test_context_uses_external_cache_and_restores_cwd(self):
        with tempfile.TemporaryDirectory() as directory:
            previous = Path.cwd()
            with patch.dict(os.environ, {"LOCALAPPDATA": directory}):
                with target.isolated_comtypes_cache() as cache_root:
                    self.assertEqual(Path.cwd(), cache_root)
                    self.assertTrue(cache_root.is_dir())
                self.assertEqual(Path.cwd(), previous)

    def test_pywinauto_import_does_not_write_to_repository(self):
        if importlib.util.find_spec("pywinauto") is None:
            self.skipTest("pywinauto is unavailable")
        with (
            tempfile.TemporaryDirectory() as working_directory,
            tempfile.TemporaryDirectory() as local_app_data,
        ):
            environment = os.environ.copy()
            environment["LOCALAPPDATA"] = local_app_data
            code = "\n".join(
                (
                    "import sys",
                    f"sys.path.insert(0, {str(SKILL_DIR)!r})",
                    "from ida_sequential import configure_comtypes_cache, isolated_comtypes_cache",
                    "with isolated_comtypes_cache() as cache_root:",
                    "    configure_comtypes_cache(cache_root)",
                    "    import pywinauto",
                    "    import comtypes.client",
                    "    print(cache_root)",
                    "    print(comtypes.client.gen_dir)",
                )
            )
            completed = subprocess.run(
                [sys.executable, "-c", code],
                cwd=working_directory,
                env=environment,
                capture_output=True,
                text=True,
                encoding="utf-8",
                check=False,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            cache_root, generated = map(Path, completed.stdout.splitlines())
            self.assertTrue(
                target.same_path(cache_root, Path(local_app_data) / "ida-sequential" / "comtypes")
            )
            self.assertTrue(generated.is_relative_to(cache_root))
            self.assertFalse((Path(working_directory) / "Python").exists())

    def test_context_falls_back_when_local_cache_is_unusable(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            blocked = root / "blocked"
            blocked.write_text("not a directory", encoding="utf-8")
            fallback = root / "fallback"
            previous = Path.cwd()
            with patch.object(
                target, "comtypes_cache_roots", return_value=(blocked, fallback)
            ):
                with target.isolated_comtypes_cache() as cache_root:
                    self.assertTrue(target.same_path(cache_root, fallback))
                    self.assertEqual(Path.cwd(), fallback)
                self.assertEqual(Path.cwd(), previous)


class ProcessIdentityTests(unittest.TestCase):
    def test_process_exe_uses_pywin32_and_always_closes(self):
        pid = 1660
        error = target.pywintypes.error(5, "OpenProcess", "Access denied")
        with patch.object(target.win32api, "OpenProcess", side_effect=error):
            self.assertIsNone(target.process_exe(pid))

        handle = object()
        executable = Path("ida64.exe")
        with (
            patch.object(target.win32api, "OpenProcess", return_value=handle) as open_process,
            patch.object(
                target.win32process,
                "GetModuleFileNameEx",
                return_value=str(executable),
            ),
            patch.object(target.win32api, "CloseHandle") as close_handle,
        ):
            self.assertEqual(target.process_exe(pid), executable)
        open_process.assert_called_once_with(
            target.win32con.PROCESS_QUERY_LIMITED_INFORMATION, False, pid
        )
        close_handle.assert_called_once_with(handle)

        with (
            patch.object(target.win32api, "OpenProcess", return_value=handle),
            patch.object(
                target.win32process,
                "GetModuleFileNameEx",
                side_effect=error,
            ),
            patch.object(target.win32api, "CloseHandle") as close_handle,
        ):
            self.assertIsNone(target.process_exe(pid))
        close_handle.assert_called_once_with(handle)


class WindowOperationTests(unittest.TestCase):
    def test_window_live_requires_existing_visible_window(self):
        with (
            patch.object(target.win32gui, "IsWindow", return_value=False),
            patch.object(target.win32gui, "IsWindowVisible") as visible,
        ):
            self.assertFalse(target.window_is_live_and_visible(100))
        visible.assert_not_called()

        with (
            patch.object(target.win32gui, "IsWindow", return_value=True),
            patch.object(target.win32gui, "IsWindowVisible", return_value=False),
        ):
            self.assertFalse(target.window_is_live_and_visible(100))

        with (
            patch.object(target.win32gui, "IsWindow", return_value=True),
            patch.object(target.win32gui, "IsWindowVisible", return_value=True),
        ):
            self.assertTrue(target.window_is_live_and_visible(100))

    def test_request_close_posts_wm_close(self):
        with patch.object(target.win32gui, "PostMessage") as post_message:
            target.request_close(123)
        post_message.assert_called_once_with(123, target.win32con.WM_CLOSE, 0, 0)

    def test_request_close_wraps_pywin32_error(self):
        error = target.pywintypes.error(5, "PostMessage", "Access denied")
        with patch.object(target.win32gui, "PostMessage", side_effect=error):
            with self.assertRaisesRegex(target.SwitchError, "window close"):
                target.request_close(123)


class ListenerQueryTests(unittest.TestCase):
    def setUp(self):
        self.endpoint = target.parse_mcp_url("http://127.0.0.1:13337/mcp")

    def query(self, output: bytes, returncode: int = 0, stderr: bytes = b""):
        result = Mock(returncode=returncode, stdout=output, stderr=stderr)
        with patch.object(target.subprocess, "run", return_value=result):
            return target.listener_pids(self.endpoint)

    def test_single_listener_including_ipv6_duplicate(self):
        output = b"\n".join(
            (
                b"  Proto  Local Address          Foreign Address        State           PID",
                b"  TCP    127.0.0.1:13337        0.0.0.0:0              LISTENING       8084",
                b"  TCP    [::]:13337             [::]:0                 LISTENING       8084",
            )
        )
        self.assertEqual(self.query(output), {8084})
        with patch.object(target.subprocess, "run", return_value=Mock(returncode=0, stdout=output, stderr=b"")):
            self.assertEqual(target.listener_pid(self.endpoint), 8084)

    def test_same_port_multiple_pids_is_ambiguous(self):
        output = b"\n".join(
            (
                b"  TCP    127.0.0.1:13337        0.0.0.0:0              LISTENING       10",
                b"  TCP    [::]:13337             [::]:0                 LISTENING       20",
            )
        )
        result = Mock(returncode=0, stdout=output, stderr=b"")
        with patch.object(target.subprocess, "run", return_value=result):
            with self.assertRaisesRegex(target.SwitchError, "Ambiguous"):
                target.listener_pid(self.endpoint)

    def test_established_connection_is_ignored(self):
        output = b"\n".join(
            (
                b"  TCP    127.0.0.1:13337        127.0.0.1:50000         ESTABLISHED     8084",
                b"  TCP    127.0.0.1:14000        0.0.0.0:0              LISTENING       42",
            )
        )
        self.assertEqual(self.query(output), set())

    def test_netstat_nonzero_exit_is_visible(self):
        result = Mock(returncode=1, stdout=b"", stderr=b"access denied")
        with patch.object(target.subprocess, "run", return_value=result):
            with self.assertRaisesRegex(target.SwitchError, "exit code 1.*access denied"):
                target.listener_pids(self.endpoint)

    def test_malformed_columns_and_ports_are_rejected(self):
        malformed = (
            b"  TCP    127.0.0.1:13337        0.0.0.0:0              LISTENING",
            b"  TCP    127.0.0.1:not-a-port   0.0.0.0:0              LISTENING       10",
            b"  TCP    127.0.0.1:70000        0.0.0.0:0              LISTENING       10",
        )
        for output in malformed:
            with self.subTest(output=output):
                with self.assertRaises(target.SwitchError):
                    self.query(output)


class WindowSelectionTests(unittest.TestCase):
    def test_rejects_when_no_main_window(self):
        tool = target.WindowCandidate(
            handle=1,
            title="IDA tool",
            class_name="Qt5153QTQWindowIcon",
            visible=True,
        )

        with self.assertRaisesRegex(target.SwitchError, "found 0"):
            target.select_main_window([tool])

    def test_ignores_hidden_quick_start_and_shadow_windows(self):
        quick_start = target.WindowCandidate(
            handle=2,
            title="IDA: Quick start",
            class_name="Qt5153QTQWindowIcon",
            visible=False,
        )
        shadow = target.WindowCandidate(
            handle=1,
            title="IDA - hidden shadow",
            class_name="PopupDropShadowSaveBits",
            visible=False,
        )
        main = target.WindowCandidate(
            handle=3,
            title="IDA - main",
            class_name="Qt5153QTQWindowIcon",
            visible=True,
        )

        self.assertEqual(target.select_main_window([quick_start, shadow, main]), 3)

    def test_selects_single_visible_main_window(self):
        windows = []
        for handle, title, class_name, visible in (
            (1, "IDA - shadow", "PopupDropShadowSaveBits", False),
            (2, "IDA: Quick start", "Qt5153QTQWindowIcon", False),
            (3, "Please wait...", "Qt5153QTQWindowIcon", False),
            (5, "IDA - main", "Qt5153QTQWindowIcon", True),
        ):
            window = Mock()
            window.handle = handle
            window.window_text.return_value = title
            window.class_name.return_value = class_name
            window.is_visible.return_value = visible
            windows.append(window)
        automation = Mock()
        automation.win32.windows.return_value = windows

        self.assertEqual(target.main_window(automation, 1660), 5)
        automation.win32.windows.assert_called_once_with(
            process=1660, visible_only=True
        )

    def test_rejects_multiple_visible_main_windows(self):
        candidates = [
            target.WindowCandidate(5, "IDA - first", "Qt5153QTQWindowIcon", True),
            target.WindowCandidate(6, "IDA - second", "Qt5153QTQWindowIcon", True),
        ]

        with self.assertRaisesRegex(target.SwitchError, "found 2"):
            target.select_main_window(candidates)


class DialogAutomationTests(unittest.TestCase):
    def test_win32_discovers_owned_save_dialog_missing_from_uia(self):
        deflate = Mock()
        deflate.window_text.return_value = "Pack database (Deflate)"
        deflate.element_info.control_type = "RadioButton"
        deflate.get_toggle_state.return_value = 1
        deflate.is_selected.return_value = False

        discard = Mock()
        discard.window_text.return_value = "DON'T SAVE the database"
        discard.element_info.control_type = "CheckBox"
        discard.get_toggle_state.return_value = 0

        confirm = Mock()
        confirm.window_text.return_value = "OK"
        confirm.element_info.control_type = "Button"

        dialog = Mock()
        dialog.handle = 6881966
        dialog.window_text.return_value = "Save database"
        dialog.class_name.return_value = "Qt5153QTQWindowIcon"
        dialog.is_visible.return_value = True
        dialog.descendants.return_value = [deflate, discard, confirm]

        uia = Mock()
        uia.windows.return_value = []
        uia.window.return_value = dialog
        win32 = Mock()
        win32.windows.return_value = [dialog]
        automation = target.AutomationDesktops(uia, win32)

        self.assertEqual(uia.windows(process=1660, visible_only=True), [])
        uia.windows.reset_mock()
        handled: set[int] = set()
        with patch.object(target, "window_is_live_and_visible", return_value=True):
            target.automate_save_dialog(automation, 1660, 99, handled)

        win32.windows.assert_called_once_with(process=1660, visible_only=True)
        uia.windows.assert_not_called()
        uia.window.assert_called_once_with(handle=6881966)
        deflate.is_selected.assert_not_called()
        deflate.select.assert_not_called()
        deflate.click_input.assert_not_called()
        confirm.click.assert_called_once_with()
        discard.toggle.assert_not_called()
        self.assertIn(6881966, handled)

    def test_radio_toggle_zero_clicks_once_then_confirms_ok(self):
        deflate = Mock()
        deflate.window_text.return_value = "Pack database (Deflate)"
        deflate.element_info.control_type = "RadioButton"
        deflate.get_toggle_state.side_effect = [0, 1]

        discard = Mock()
        discard.window_text.return_value = "DON'T SAVE the database"
        discard.element_info.control_type = "CheckBox"
        discard.get_toggle_state.return_value = 0

        confirm = Mock()
        confirm.window_text.return_value = "OK"
        confirm.element_info.control_type = "Button"

        with patch.object(target.time, "sleep") as sleep:
            handled = target.save_dialog_controls([deflate, discard, confirm])

        self.assertTrue(handled)
        deflate.click_input.assert_called_once_with()
        deflate.select.assert_not_called()
        sleep.assert_called_once_with(target.TOGGLE_POLL_SECONDS)
        confirm.click.assert_called_once_with()

    def test_destroyed_window_is_skipped_before_uia_binding(self):
        dialog = Mock()
        dialog.handle = 6881966
        dialog.window_text.return_value = "Save database"
        dialog.class_name.return_value = "Qt5153QTQWindowIcon"
        dialog.is_visible.return_value = True
        uia = Mock()
        win32 = Mock()
        win32.windows.return_value = [dialog]
        automation = target.AutomationDesktops(uia, win32)

        with patch.object(target, "window_is_live_and_visible", return_value=False):
            target.automate_save_dialog(automation, 1660, 99, set())

        uia.window.assert_not_called()
        dialog.descendants.assert_not_called()


class IdentityTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.root = Path(self.temp_dir.name)
        self.executable = self.root / "ida64.exe"
        self.executable.write_bytes(b"")
        self.input_path = self.root / "current.exe"
        self.database_path = self.root / "current.exe.idb"

    def health(self, ready: bool = True) -> dict:
        return {
            "status": "ok",
            "input_path": str(self.input_path),
            "idb_path": str(self.database_path),
            "auto_analysis_ready": ready,
        }

    def test_accepts_matching_input_path(self):
        session = target.session_from_health(
            17, self.executable, self.health(), self.input_path
        )

        self.assertEqual(session.pid, 17)
        self.assertEqual(session.input_path, self.input_path)
        self.assertEqual(session.idb_path, self.database_path)
        self.assertTrue(target.same_path(self.input_path, str(self.input_path).upper()))
        self.assertTrue(
            target.same_path(self.input_path, str(self.input_path).replace("\\", "/"))
        )

    def test_accepts_matching_database_path(self):
        session = target.session_from_health(
            17, self.executable, self.health(), self.database_path
        )

        self.assertEqual(session.idb_path, self.database_path)

    def test_rejects_identity_mismatch(self):
        with self.assertRaisesRegex(target.SwitchError, "Expected"):
            target.session_from_health(
                17, self.executable, self.health(), self.root / "other.exe"
            )

    def test_rejects_unrecognized_database(self):
        health = self.health()
        health["idb_path"] = str(self.root / "current.bin")

        with self.assertRaisesRegex(target.SwitchError, "Unrecognized"):
            target.session_from_health(17, self.executable, health)

    def test_status_identity_can_be_pending(self):
        session = target.session_from_health(
            17, self.executable, self.health(False), require_ready=False
        )

        self.assertFalse(session.health["auto_analysis_ready"])

    def test_save_path_must_match_current_database(self):
        with self.assertRaisesRegex(target.SwitchError, "unexpected path"):
            target.verify_save(
                {"ok": True, "path": str(self.root / "other.exe.idb")},
                self.database_path,
            )


class SwitchTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.root = Path(self.temp_dir.name)
        self.endpoint = target.parse_mcp_url("http://127.0.0.1:13337/mcp")
        self.executable = self.root / "ida64.exe"
        self.current_input = self.root / "current.exe"
        self.current_database = self.root / "current.exe.idb"
        self.next_input = self.root / "next.exe"
        self.executable.write_bytes(b"")
        self.current_input.write_bytes(b"")
        self.current_database.write_bytes(b"database")
        self.next_input.write_bytes(b"")

    def current_health(self) -> dict:
        return {
            "status": "ok",
            "input_path": str(self.current_input),
            "idb_path": str(self.current_database),
            "auto_analysis_ready": True,
        }

    def next_health(self) -> dict:
        return {
            "status": "ok",
            "input_path": str(self.next_input),
            "idb_path": str(self.root / "next.exe.idb"),
            "auto_analysis_ready": True,
        }

    def test_normal_switch_saves_closes_and_opens_next(self):
        runtime = FakeRuntime(self.executable)
        client = Mock(spec=target.McpClient)
        client.health.side_effect = [self.current_health(), self.next_health()]
        client.tool.return_value = {"ok": True, "path": str(self.current_database)}
        sequencer = target.IdaSequencer(
            self.endpoint, 10, client=client, runtime=runtime
        )

        session = sequencer.next(
            self.next_input, self.current_input, self.executable
        )

        self.assertEqual(session.pid, runtime.new_pid)
        self.assertEqual(runtime.open_path, self.next_input)
        self.assertIn("prepare", runtime.events)
        self.assertIn("close", runtime.events)
        self.assertIn("launch", runtime.events)
        client.tool.assert_called_once_with("idb_save", timeout=10)

    def test_next_without_ida_reuses_current_process_executable(self):
        runtime = FakeRuntime(self.executable)
        client = Mock(spec=target.McpClient)
        client.health.side_effect = [self.current_health(), self.next_health()]
        client.tool.return_value = {"ok": True, "path": str(self.current_database)}
        sequencer = target.IdaSequencer(
            self.endpoint, 10, client=client, runtime=runtime
        )

        session = sequencer.next(self.next_input, self.current_input)

        self.assertEqual(session.pid, runtime.new_pid)
        self.assertEqual(runtime.launch_executable, self.executable)
        self.assertEqual(runtime.open_path, self.next_input)

    def test_save_failure_keeps_current_session(self):
        runtime = FakeRuntime(self.executable)
        client = Mock(spec=target.McpClient)
        client.health.return_value = self.current_health()
        client.tool.return_value = {"ok": False, "path": str(self.current_database)}
        sequencer = target.IdaSequencer(
            self.endpoint, 10, client=client, runtime=runtime
        )

        with self.assertRaisesRegex(target.SwitchError, "idb_save failed"):
            sequencer.next(self.next_input, self.current_input, self.executable)

        self.assertFalse(runtime.closed)
        self.assertFalse(runtime.launched)

    def test_startup_timeout_reports_last_reason(self):
        runtime = FakeRuntime(self.executable)
        runtime.owner = None
        runtime.launched = True
        runtime.clock_values = iter((0.0, 2.0))
        client = Mock(spec=target.McpClient)
        sequencer = target.IdaSequencer(
            self.endpoint, 1, client=client, runtime=runtime
        )

        with self.assertRaisesRegex(
            target.SwitchError, "not verified within 1s"
        ):
            sequencer._wait_ready(
                runtime.new_pid,
                self.executable,
                self.next_input,
                self.next_input,
            )

        client.health.assert_not_called()

    def test_wait_closed_accepts_disconnected_dialog_after_process_exit(self):
        runtime = FakeRuntime(self.executable)
        client = Mock(spec=target.McpClient)
        sequencer = target.IdaSequencer(
            self.endpoint, 10, client=client, runtime=runtime
        )
        current = target.IdaSession(
            runtime.current_pid,
            self.executable,
            self.current_input,
            self.current_database,
            {},
        )
        calls = 0

        def disconnected_after_dialog(*args):
            nonlocal calls
            calls += 1
            if calls == 2:
                runtime.closed = True
                runtime.owner = None
                raise target.SwitchError("disconnected dialog")

        with patch.object(
            target, "automate_save_dialog", side_effect=disconnected_after_dialog
        ):
            sequencer._wait_closed(current, 101, Mock())

        self.assertEqual(calls, 2)


class CliFailureTests(unittest.TestCase):
    def test_parser_allows_next_without_ida(self):
        args = target.build_parser().parse_args(
            ["next", "next.exe", "--expect-current", "current.exe"]
        )
        self.assertIsNone(args.ida)

    def test_parser_requires_ida_for_open(self):
        stderr = StringIO()
        with redirect_stderr(stderr), self.assertRaises(SystemExit) as raised:
            target.build_parser().parse_args(["open", "sample.exe"])
        self.assertEqual(raised.exception.code, 2)
        self.assertIn("--ida", stderr.getvalue())

    def test_switch_error_returns_nonzero(self):
        stderr = StringIO()
        with (
            patch.object(
                target.IdaSequencer,
                "status",
                side_effect=target.SwitchError("status failed"),
            ),
            redirect_stderr(stderr),
        ):
            result = target.cli(["status"])

        self.assertEqual(result, 1)
        self.assertIn("ERROR: status failed", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
