# IDA Pro 8.3 + Codex：单 MCP 顺序切换文件

**环境：** Windows IDA Pro 8.3 GUI、`mrexodia/ida-pro-mcp` 主分支 GUI 插件、现有 `http://127.0.0.1:13337/mcp`。**不修改 Codex 配置，不新增 MCP。**

## 安装与准备

```powershell
python -m pip install pywinauto
```

将 `ida_sequential.py` 放在 Windows 机器上（例如 `D:\reverse-workspace\ida_sequential.py`），与 IDA 在**同一个交互式桌面会话、相同权限级别**下执行。IDA 插件需开启 MCP 自动启动，端口固定为 **13337**。不要同时运行另一个占用该端口的服务。

## 操作

查看当前 IDA / MCP：

```powershell
python D:\reverse-workspace\ida_sequential.py status
```

如果已在 IDA 中打开 `A.exe`，完成分析后自动切换到 `B.dll`：

```powershell
python D:\reverse-workspace\ida_sequential.py next `
  "D:\samples\B.dll" `
  --expect-current "D:\samples\A.exe" `
  --timeout 600
```

首次启动（当前无人占用 13337）：

```powershell
python D:\reverse-workspace\ida_sequential.py open `
  "D:\samples\A.exe" `
  --ida "C:\IDA83\ida64.exe" `
  --timeout 600
```

`--expect-current` 必须匹配 `server_health` 中当前输入文件路径或当前 IDB 路径。`--timeout` 是每个主要等待阶段的上限（秒）。

## 切换流程

1. 通过 Windows IP Helper API 查询 **13337 监听 PID**，确认属于 IDA GUI，再调用现有 MCP 的 `server_health` 验证文件身份。
2. 检查下一文件、当前 IDB、IDA 主窗口以及 Windows UI Automation 可用性。
3. 直接调用当前 `/mcp` 上的 **`idb_save`**（原地保存）；返回 `ok != true` 就停止，不关闭 IDA。
4. 向正确 PID 的 IDA 主窗口发送 `WM_CLOSE`。如果出现 **Save database**：选择 `Pack database (Deflate)`（无此选项则 `Store`）、取消 `DON'T SAVE the database` 并点击 `OK`。不依赖人工点击。
5. 等待旧 IDA 退出，验证 13337 端口释放、IDB 文件存在且非空；没有强制结束进程的分支。
6. 用 **IDA 8.3 支持的** `-A -P+` 参数启动新 IDA，优先打开下一文件已有的 `.i64/.idb`；等待新 PID 持有 13337，检查输入/IDB 路径且 `auto_analysis_ready == true`，然后返回成功。

### IDA 8.3 启动参数核对

- `-A`：自主模式，使用默认选项处理加载提示。会持续抑制交互对话框；后续需要手动操作时可在 IDA 控制台执行 `batch(0)` 恢复交互。
- `-P+`：压缩保存数据库；不改变分析文件类型。
- **不使用 `-B`**：它属于自动反汇编并退出的批处理流程，不适合维持 GUI MCP 服务。

这两个参数已见于 **2022 年的命令行说明（早于 IDA 8.3 发布）**，且在 IDA 8.4 官方文档中仍然存在。因此参数层面适配 8.3；但 **IDA 8.3 + MCP GUI 的完整启动/切换尚未在你的机器上实测**。`-A` 不保证第三方插件/非标准加载器的每个提示都可自动处理；加载或连接未通过验证时脚本会超时并报错，而非误报成功。

**故障约束：** 无法安全识别的对话框、保存失败、多个可选 IDB、目标身份不一致、进程退出异常、端口抢占或超时，均返回非零退出码并停止切换；**不按未知弹窗、不删除 IDB、不使用 `taskkill /F`**。若新 IDA 启动后无法就绪，保留进程供排查。

## 给 Codex 的任务指令

```text
依次分析样本，不并行，也不要修改现有 MCP 配置。
每个文件先使用已有 MCP 的 server_health 核对文件路径；
逆向完成后保存独立报告，再运行：
python D:\reverse-workspace\ida_sequential.py next "下一个文件绝对路径" --expect-current "当前输入文件绝对路径" --timeout 600
只有脚本返回 0，且新 server_health 指向下一文件，才开始下一轮分析。
遇到切换异常立即停止，保留现有 IDA 和数据库，不强制关闭。
```

## 实现依据与测试范围

- [主分支 `idb_save` 源码](https://github.com/mrexodia/ida-pro-mcp/blob/main/src/ida_pro_mcp/ida_mcp/api_core.py)：原地保存调用 `ida_loader.save_database(None, 0)`。
- [主分支 `server_health` 源码](https://github.com/mrexodia/ida-pro-mcp/blob/main/src/ida_pro_mcp/ida_mcp/api_core.py)：返回 `input_path`、`idb_path`、`auto_analysis_ready`。
- [2022 年的 IDA 命令行参数说明](https://www.idapro.net.cn/faq/ida-dhsuqz.html)：在 IDA 8.3 发布之前已列出 `-A` 和 `-P+`。
- [Hex-Rays 官方 IDA 8.4 命令行参数文档](https://docs.hex-rays.com/8.4/user-guide/configuration/command-line-switches)：再次确认两个参数；**不再引用 9.0 文档作为 8.3 的依据**。
- [Hex-Rays 命令行使用指南](https://hex-rays.com/blog/igor-tip-of-the-week-07-ida-command-line-options-cheatsheet)：解释 `-A` 的行为和 `batch(0)` 恢复交互的方法。
- Python 语法检查与模拟测试（见本次验证）；**尚未在你的 Windows + IDA Pro 8.3 GUI 上进行端到端实测**。
