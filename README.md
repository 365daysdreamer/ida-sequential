# IDA Sequential

通过已有的 `ida-pro-mcp` 端点，在一个 Windows 桌面会话中依次分析多个文件。每次切换会保存并正常关闭当前 IDA GUI，再启动下一文件，并核对新的进程与数据库身份。

## 环境准备

需要 Windows 交互式桌面、IDA Pro 8.3 GUI，以及已启用 GUI 模式的 `ida-pro-mcp`。脚本与 IDA 应处于相同桌面会话和权限级别。

配置本机回环 MCP 地址：

```text
[mcp_servers.ida-pro-mcp]
url = "<MCP_URL>"
```

## 确认 Python 解释器

脚本需要独立 Python 解释器。IDA 内嵌环境中的 `sys.executable` 常指向 `ida.exe`，解释器应以 `sys.base_prefix` 推导：

```python
import sys
from pathlib import Path

{
    "python_home": str(Path(sys.base_prefix) / "python.exe"),
    "python_version": sys.version,
}
```

若 `ida-pro-mcp` 已连接且提供 `py_eval`，用它执行上述只读代码。该工具会在 IDA 进程内执行代码，只适用于可信的本机回环端点。

MCP 未连接、`py_eval` 不可用或推导路径不存在时，向用户索取 `<PYTHON_EXE>`。路径确认一次后用于后续命令：

```powershell
$Python = "<PYTHON_EXE>"
Test-Path -LiteralPath $Python -PathType Leaf
& $Python -c "import pywinauto, win32api; print('dependencies ready')"
```

依赖缺失时安装：

```powershell
& $Python -m pip install pywinauto pywin32
```

## 基本参数

```powershell
Set-Location "<REPO_ROOT>"
$Ida = "<IDA_EXE>"
$McpUrl = "<MCP_URL>"
$Timeout = 600
```

`--ida` 指向 IDA GUI 可执行文件。`--timeout` 控制关闭与启动等待的上限，单位为秒。

## 查看状态

```powershell
& $Python scripts/ida_sequential.py status --mcp-url $McpUrl
```

输出包含 `pid`、`ida_path`、`mcp_url` 和 `server_health`。验收时检查：

- `server_health.status` 为 `ok`
- `input_path` 指向当前样本
- `idb_path` 指向当前数据库
- `auto_analysis_ready` 为 `true`

## 首次打开

MCP 端口空闲且没有 IDA 实例时：

```powershell
& $Python scripts/ida_sequential.py open "<SAMPLE>" `
  --ida $Ida `
  --mcp-url $McpUrl `
  --timeout $Timeout
```

命令成功后，新 IDA 进程应持有 MCP 端口，输入路径和数据库身份通过检查。

## 切换到下一文件

```powershell
& $Python scripts/ida_sequential.py next "<NEXT_SAMPLE>" `
  --expect-current "<CURRENT_SAMPLE>" `
  --ida $Ida `
  --mcp-url $McpUrl `
  --timeout $Timeout
```

`--expect-current` 核对当前样本或 IDB 身份。

每轮顺序分析按以下流程执行：

1. 完成当前文件分析，若有相关分析技能则自动调用，将结果写入独立报告。
2. 运行 `status`，核对 PID、输入路径、IDB 和 `auto_analysis_ready`。
3. 运行 `next`。脚本调用 `idb_save`，正常关闭 IDA，等待旧 PID 退出、端口释放且 IDB 非空。
4. 脚本启动下一文件，核对新 PID、输入路径、IDB 和 `auto_analysis_ready`。
5. 确认 `next` 退出码为 `0`，并用 `status` 或 MCP 的 `server_health` 复核新文件。
6. 复核通过后进入下一轮分析。

保存对话框出现时，脚本接受可识别的 `Pack database (Deflate)` 或 `Pack database (Store)`。它会确认 `DON'T SAVE` 未选中，再点击 `OK`。

IDA 以 `-A -P+` 启动。`-B` 会进入自动分析后退出的批处理流程，无法维持 GUI MCP 服务。

多个文件串行处理，并保持一个 IDA GUI 实例和一个 MCP 监听。

## 失败处理

出现以下情况时终止本轮流程：

- 端口归属不明确，或端口属于非 IDA 进程。
- 当前样本、IDB 或 IDA 可执行文件不匹配。
- `idb_save` 失败，或返回不同路径。
- 保存对话框无法安全识别。
- 旧进程未退出、端口未释放，或 IDB 为空。
- 新进程未启动、端口被其他 PID 占用，或分析尚未就绪。
- 命令返回非零退出码。

失败后保留 IDA、IDB 和终端输出。通过 `status`、可见窗口和错误信息确认现场，再决定是否重试。脚本不会强制结束 IDA。

## 测试

```powershell
& $Python -m unittest discover -s tests -v
```

测试使用临时目录和模拟对象。
