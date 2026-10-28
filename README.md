# IDA Pro MCP

在 IDA Pro 里做 AI 辅助逆向：把 IDA 的数据库能力通过 [MCP](https://modelcontextprotocol.io) 暴露给 Claude Code、Cline、Cursor 等客户端。

- 当前版本：**1.7.0**
- 支持 IDA Pro **8.3+**（重点适配 **IDA 9.x / 9.5**）
- 运行时：`mcp` **2.x**（`MCPServer` API）
- License：MIT

---

## 1. 它由两个进程组成

```text
┌──────────────────────────┐        stdio / SSE        ┌──────────────────────────┐
│ MCP 客户端                │ ◄───────────────────────► │ Gateway                  │
│ (Claude Code / Cline ...)│                           │ ida-pro-mcp (server.py)  │
└──────────────────────────┘                           └────────────┬─────────────┘
                                                                    │ HTTP JSON-RPC
                                                                    │ http://127.0.0.1:<port>/mcp
                                                    ┌───────────────┴────────────────┐
                                                    │                                │
                                          ┌─────────▼─────────┐            ┌─────────▼─────────┐
                                          │ IDA GUI 插件       │            │ idalib headless    │
                                          │ mcp-plugin.py     │            │ worker (每库一进程) │
                                          │ 自带 MCP/HTTP 实现 │            │ idalib_server.py   │
                                          └───────────────────┘            └───────────────────┘
```

| 组件 | 文件 | 作用 |
|---|---|---|
| **IDA 插件** | `src/ida_pro_mcp/mcp-plugin.py` | 在 IDA 进程内运行，实现全部 IDA 工具；自带 HTTP/SSE/JSON-RPC，**不依赖 `mcp` 库**，可单文件部署 |
| **Gateway** | `src/ida_pro_mcp/server.py` | MCP 客户端唯一入口；发现所有 IDA 实例并转发调用；支持多数据库 |
| **工具壳（自动生成）** | `src/ida_pro_mcp/server_generated.py` | 启动 Gateway 时用 AST 从 `mcp-plugin.py` 自动生成，**不要手改** |
| **headless 服务** | `src/ida_pro_mcp/idalib_server.py` | 无 GUI 的 idalib 模式，或作为 Gateway 的 worker 子进程 |
| **实例注册表** | `src/ida_pro_mcp/discovery.py` | 读写 `%TEMP%/ida-pro-mcp/instances/*.json`，用于发现/清理实例 |

> 关键点：GUI 插件和 Gateway 是**两套独立安装**。插件坏了不影响 Gateway；Gateway 的 Python/mcp 版本也不会影响已加载的插件。

---

## 2. 环境要求

| 依赖 | 要求 |
|---|---|
| IDA Pro | 8.3+；推荐 9.x（9.5 已验证） |
| IDA 的 Python | 3.11+（用 `idapyswitch` 切换） |
| Gateway 的 Python | 3.11+，与 IDA 的 Python 可以不同 |
| `uv` | 用于安装/运行 Gateway |

检查 IDA 实际使用的 Python：

```text
IDA 菜单 → Help → About，或在 IDAPython 控制台执行：
import sys; print(sys.version)
```

---

## 3. 安装

### 3.1 安装 Gateway 依赖

```bash
cd <项目目录>
uv sync
```

这会创建/更新 `.venv`，安装 `mcp>=2.3,<3`、`pydantic>=2.14`、`httpx` 等。

> **不要**在项目目录外用系统 Python 直接跑 `ida-pro-mcp`。旧副本可能缺少 `src/` 路径或使用 mcp 1.x，导致 `No module named 'ida_pro_mcp'` / `'mcp.server.fastmcp'`。

### 3.2 安装 IDA 插件

IDA 9.x 推荐使用**包形式**（本仓库根目录就是一个插件包）：

```text
<IDADIR>/plugins/ida-pro-mcp-main/
├── ida-plugin.json          # name = "IDA Pro MCP", entryPoint = src/ida_pro_mcp/mcp-plugin.py
└── src/ida_pro_mcp/mcp-plugin.py
```

把项目目录放到 IDA 的插件目录（`<IDADIR>/plugins/` 或 `%APPDATA%\Hex-Rays\IDA Pro\plugins/`），IDA 会按 `ida-plugin.json` 的 `entryPoint` 加载。

也可以使用传统单文件方式：

```bash
uv run ida-pro-mcp --install       # 软链/复制 mcp-plugin.py 到 %APPDATA%\Hex-Rays\IDA Pro\plugins\
```

> **不要同时保留两种安装**。如果旧的单文件软链指向一个已删除的 IDA 目录，IDA 会创建一个空模块，菜单里可能出现重复项。删掉悬空软链即可。

### 3.3 配置 MCP 客户端

```bash
uv run ida-pro-mcp --install --no-plugin   # 只写 MCP 客户端配置（已用包形式安装插件时用这个）
uv run ida-pro-mcp --install               # 同时安装传统单文件插件 + 写客户端配置
uv run ida-pro-mcp --config                # 只打印配置，不写入
```

Claude Code 的配置形如：

```json
{
  "mcpServers": {
    "ida-pro-mcp": {
      "command": "<项目目录>\\.venv\\Scripts\\python.exe",
      "args": ["-m", "ida_pro_mcp.server"],
      "env": { "PYTHONPATH": "<项目目录>\\src" },
      "timeout": 600000
    }
  }
}
```

各客户端的差异：

| 客户端 | 配置文件 | `timeout` 单位 | 权限字段 |
|---|---|---|---|
| Claude Code | `~/.claude.json` | **毫秒**（推荐 `600000`） | `permissions.allow` |
| Cline / Roo Code / Kilo Code | `*_mcp_settings.json` / `mcp_settings.json` | **秒**（推荐 `1800`） | `autoApprove` / `alwaysAllow` |
| Claude Desktop / Cursor / Windsurf / LM Studio | 各自 JSON | 秒 | 忽略 |
| Codex | `~/.codex/config.toml` | 秒 | 忽略 |

> 把 Cline 的 `1800` 直接粘到 Claude Code 会被当成 **1.8 秒**，慢工具必然超时；把 Claude Code 的 `600000` 粘到 Cline 则是 600000 秒。

### 3.4 验证

1. 打开 IDA 并加载一个数据库。
2. `Edit → Plugins → MCP`（快捷键 `Ctrl+Alt+M`）。
3. 重启 MCP 客户端（Claude Code 需要完全退出托盘进程）。
4. 调用 `check_connection()` 或 `list_databases()`。

---

## 4. 使用

### 4.1 基本流程

```text
check_connection()                 # 确认插件在运行
list_databases()                   # 看有哪些数据库
use_database("<id>")               # 设为默认（可选）
get_metadata()                     # 看当前库信息
list_functions(0, 20)              # 浏览函数
decompile_function("0x401000")     # 反编译
set_comment("0x401000", "说明")     # 写注释
rename_function("0x401000", "decrypt")  # 重命名
```

所有从插件转发的工具都额外接受一个可选参数：

```text
database: "<id | module | port>"   # 覆盖本次调用的目标库
```

### 4.2 多数据库

一个 Gateway 进程即可管理多个数据库，**不需要为每个库单独配置 MCP server/端口**。

- 每个 IDA GUI 实例启动插件后，在 `%TEMP%/ida-pro-mcp/instances/` 写入 `{id, host, port, module, pid, kind, heartbeat}`；端口从 `13337` 起递增。
- 每个 headless worker 使用系统分配的端口，也写入同一个注册表。
- Gateway 读取注册表、清理死进程/过期心跳，然后按调用路由。

选择优先级：

```text
调用参数 database  >  use_database(id) 设的默认  >  唯一的实例自动选中
```

存在多个实例且未指定时会报错并列出可用 id。不同库的调用并发执行；同一个库由 IDA 自身串行化。

示例：

```text
list_databases()
# [{"id":"148788cb-13339","module":"Sky.exe","port":13339,"kind":"gui"}, ...]

get_metadata(database="148788cb-13339")
use_database("5080cb35-13337")
```

### 4.3 headless / idalib 模式

```bash
uv run idalib-mcp --host 127.0.0.1 --port 8745 path/to/binary
# 或不带文件，启动后再用 load_database() 动态加载
uv run idalib-mcp --host 127.0.0.1 --port 8745
```

对应工具：

```text
load_database(path, run_auto_analysis=True)   # 启动一个独立 worker 进程
close_database(id)                            # 关闭并终止 worker
save_database(id, path)                       # 保存 .idb/.i64
get_database_status()                         # 查看已加载的库
```

> IDA 的 kernel 是进程级单例，所以每个 headless 数据库都需要独立进程。

### 4.4 SSE / 远程连接

```bash
uv run ida-pro-mcp --transport http://127.0.0.1:8744/sse
```

这会以 SSE 方式暴露 Gateway。无特殊需求时推荐 stdio（客户端自动拉起）。

---

## 5. 工具参考

共 **90** 个工具：7 个 Gateway 工具 + 65 个安全 IDA 工具 + 18 个 `--unsafe` 调试器工具。

### 5.1 连接与数据库（Gateway）

| 工具 | 说明 |
|---|---|
| `check_connection` | 检查是否有 IDA 实例连接 |
| `list_databases` | 列出所有数据库（GUI + headless） |
| `use_database` | 设置本会话默认数据库 |
| `load_database` | 以 headless worker 加载二进制/IDB |
| `close_database` | 关闭 headless 数据库 |
| `save_database` | 保存数据库 |
| `get_database_status` | 当前选择与所有实例状态 |

### 5.2 元数据与基础

| 工具 | 说明 |
|---|---|
| `get_metadata` | 路径、模块名、基址、大小、MD5/SHA256/CRC32 |
| `convert_number` | 十进制/十六进制/字节/ASCII/二进制互转 |
| `get_current_address` | IDA 中当前光标地址 |
| `get_current_function` | IDA 中当前选中函数 |

### 5.3 函数

| 工具 | 说明 |
|---|---|
| `get_function_by_name` | 按名称查函数 |
| `get_function_by_address` | 按地址查函数 |
| `list_functions` | 分页列出函数 |
| `list_functions_filter` | 带过滤的分页函数列表 |
| `get_callees` | 被当前函数调用的函数 |
| `get_callers` | 调用当前函数的函数 |
| `get_entry_points` | 所有入口点 |

### 5.4 反编译、反汇编、CFG

| 工具 | 说明 |
|---|---|
| `decompile_function` | Hex-Rays 反编译 |
| `disassemble_function` | 结构化反汇编（参数、栈帧、指令） |
| `get_function_cfg` | 基本块、后继/前驱、入口/出口块 |

### 5.5 交叉引用

| 工具 | 说明 |
|---|---|
| `get_xrefs_to` | 指向某地址的所有引用 |
| `get_xrefs_to_field` | 指向某结构体成员的所有引用 |
| `who_references` | 一次返回直接 xref/callers + vtable/函数指针槽；虚函数/回调优先用 |

### 5.6 数据浏览

| 工具 | 说明 |
|---|---|
| `list_globals` / `list_globals_filter` | 全局变量 |
| `list_imports` | 导入表（带所属模块） |
| `list_strings` / `list_strings_filter` | 字符串 |
| `list_segments` | 段 |
| `list_local_types` | 本地类型 |
| `get_defined_structures` | 已定义结构体 |

### 5.7 类型与结构体

| 工具 | 说明 |
|---|---|
| `analyze_struct_detailed` | 结构体完整成员分析 |
| `get_struct_info_simple` | 结构体简要信息 |
| `get_struct_at_address` | 读取某地址上的结构体实例值 |
| `search_structures` | 按名称搜索结构体 |
| `declare_c_type` | 用 C 声明创建/更新类型 |

### 5.8 重命名与类型设置

| 工具 | 说明 |
|---|---|
| `rename_function` | 重命名函数 |
| `rename_global_variable` | 重命名全局变量 |
| `rename_local_variable` | 重命名局部变量 |
| `set_function_prototype` | 设置函数原型 |
| `set_global_variable_type` | 设置全局变量类型 |
| `set_local_variable_type` | 设置局部变量类型 |

### 5.9 栈帧

| 工具 | 说明 |
|---|---|
| `get_stack_frame_variables` | 列出栈帧变量 |
| `create_stack_frame_variable` | 创建栈帧变量 |
| `set_stack_frame_variable_type` | 设置栈帧变量类型 |
| `delete_stack_frame_variable` | 删除栈帧变量 |
| `rename_stack_frame_variable` | 重命名栈帧变量 |

### 5.10 注释与补丁

| 工具 | 说明 |
|---|---|
| `get_comments` | 常规/可重复/前置/后置/函数注释 |
| `set_comment` | 设置注释 |
| `add_comment` | 添加指定类型注释 |
| `delete_comment` | 删除指定类型注释 |
| `patch_address_assembles` | 汇编指令并写入内存 |

### 5.11 内存、搜索、脚本

| 工具 | 说明 |
|---|---|
| `read_memory_bytes` | 读取任意大小内存 |
| `data_read_byte` / `word` / `dword` / `qword` | 定宽读取 |
| `data_read_string` | 读取字符串 |
| `get_global_variable_value_by_name` | 按名称读取全局变量值 |
| `get_global_variable_value_at_address` | 按地址读取全局变量值 |
| `search_bytes` | 带 `??` 通配符的字节搜索 |
| `execute_script` | 执行任意 IDAPython；`timeout_seconds` 会真正中断脚本（0 = 不限制） |

### 5.12 调试器（需要 `--unsafe`）

```text
dbg_get_registers
dbg_get_registers_for_thread
dbg_get_registers_for_thread_current
dbg_get_registers_general_for_thread
dbg_get_registers_general_for_thread_current
dbg_get_registers_specific_for_thread
dbg_get_registers_specific_for_thread_current
dbg_get_call_stack
dbg_list_breakpoints
dbg_start_process
dbg_exit_process
dbg_continue_process
dbg_run_to
dbg_set_breakpoint
dbg_step_into
dbg_step_over
dbg_delete_breakpoint
dbg_enable_breakpoint
```

默认不会注册到 Gateway；启动时加 `--unsafe` 才可用。

---

### 5.13 虚表 / 虚函数

| 工具 | 说明 |
|---|---|
| `list_vtables` | 扫描数据段，找连续的“指向函数的指针”数组作为 vtable 候选 |
| `find_vtable_refs` | 给定函数地址，找出它作为虚函数指针出现在哪个 vtable、第几槽、偏移多少 |
| `analyze_vtable` | 读取某个 vtable 的 slots、目标函数、已绑定的 vftable 类型 |
| `walk_type_registry` | 调试会话下遍历运行时类型/元类注册表（批量读取并缓存） |
| `dump_metaclass_strings` | 扫描运行时 MetaSystem 对象，导出类/成员/方法名字符串 |
| `dump_class_metadata_strings` | 从某个 MetaClass 实例出发，扫描其元数据区域的内联/静态字符串 |
| `create_vftable_type` | 生成 vftable 结构体类型，`set_vftable_ea` 绑定地址并应用类型 |
| `rename_vfuncs` | 把目标函数重命名为 `Class::vfunc_NN`，并添加 vtable → function 的 data xref |
| `annotate_vtable` | 一键完成：建类型 + 绑定 + 重命名 + xref |

典型流程：

```text
who_references("0x141985CD0")
# → {direct_refs: [], callers: [], is_virtual: true,
#    vtable_refs: [{pointer_slot: 0x141F72468, vtable_start: 0x141F723E0,
#                   slot_index: 17, slot_offset: 0x88, installers: [...]}]}

analyze_vtable("0x141F723E0")
annotate_vtable("0x141F723E0", class_name="CMyClass")
```

说明：

- 小函数如果 `get_xrefs_to` / `get_callers` 为空，先试 `who_references`；它会同时扫描 vtable/函数指针槽。
- 扫描是启发式（连续函数指针），`min_slots` 可过滤误报；也可以先用 RTTI/构造函数定位。
- 相邻 vtable 常紧挨着存放：工具会把“被代码引用的内部地址”（通常是下一个表的构造函数/注册点）当作边界自动切分。
- `create_vftable_type` 用每个目标函数的原型生成函数指针成员。
- 动态分派本身不会变成直接调用；要让 Hex-Rays 显示 `obj->vfunc()`，还需要把类指针类型应用到对象/`this`。

运行时类型/元类注册表（需要 IDA 调试器；Sky.exe 示例）：

```text
# 0x1423D7AF0 是保存类型链表头的全局 qword
walk_type_registry("0x1423D7AF0", "Meta")
# → MetaClass / MetaSystem / 其他名字匹配的类型，含 node/vtable/instance/base

walk_type_registry("0x1423D7AF0", "AccountCurrency")
```

按字符串查元类名/成员名（需要先拿到 `MetaSystem` 实例地址）：

```text
walk_type_registry("0x1423D7AF0", "MetaSystem", 1, 4000)
# → instance = 0x9119EB0（每次启动会变）

dump_metaclass_strings("0x9119EB0", substring="Transform")
# → GetTransform / SetTransform

dump_metaclass_strings("0x9119EB0", substring="Get")
# → GetEnabled / GetIcon / GetNpc / GetObb / GetResumeEnabled / GetShopName / GetTransform ...
```

按类 dump（类成员/类型名常常是堆上的**内联字符串**，不是静态字符串指针）：

```text
walk_type_registry("0x1423D7AF0", "AccountBarn", 1, 4000)
# → instance = 0x53D03C0

dump_class_metadata_strings("0x53D03C0", substring="Color")
# → Color

dump_class_metadata_strings("0x53D03C0", window=2048)
# → Color, SystemHeap, TgcString, float, int8_t, uint32_t, uint64_t, uint8_t ...
```

说明：

- `dump_class_metadata_strings` 从 MetaClass 对象的 `+0x40/+0x48/+0x50/+0x58` 容器指针出发，按 `window` 字节向前扫描，同时提取内联 ASCII 字符串和指向静态字符串的指针。
- 窗口会覆盖相邻元数据，可能混入附近的名字；用 `substring` 精确过滤。
- 只解析可读区域；更大的结构可以加大 `window`（上限 0x4000）。

- `dump_metaclass_strings` 扫描 MetaSystem 对象内部的指针字段，解析指向静态字符串的引用；这是全局类/方法名的来源。
- 它不依赖 Lua 的 `__vars` / `__funs`（Sky 里通常是空的）；Lua 侧只有 `__ctype` / `__isclass` / `__metadata`（ClearMemory / ModuleGroup）。
- 类成员/类型名常常是堆元数据里的内联字符串，用 `dump_class_metadata_strings`；更深层的容器/哈希表仍需要额外解析。

- 缓存按 `registry_global` 保存；首次调用读取并缓存，后续查询只过滤缓存。
- 传 `refresh=True` 可在目标重载/类型动态增加后重建。
- 节点布局是 Sky 引擎的观察结果（+0x00 vtable、+0x08 name、+0x18 base、+0x28 instance），其他引擎需要调整。
- 元类内部的 `(name, value)` 元数据列表不在类型节点里，而由游戏的 `PrintMetaClassMem` / `DumpMetaSystem` 命令上下文持有；需要在 `sub_141359F60` 命中时读 `RCX` 后按 `[RCX+0xB8] → +8 → +0x108` 遍历。



## 6. 开发

### 6.1 添加一个新工具

只需要在 `mcp-plugin.py` 里加函数，Gateway 会自动生成对应的 MCP 工具：

```python
@jsonrpc
@idaread                      # 读：封送到 IDA 主线程 MFF_READ；写用 @idawrite
def my_tool(
    arg: Annotated[str, "参数说明"],     # Annotated 的字符串会变成 schema description
) -> SomeTypedDict:
    """工具描述（会显示给 LLM）"""
    ...
```

规则：

- 必须有 `@jsonrpc`；否则 Gateway 看不到。
- 所有 IDA API 调用都应加 `@idaread` 或 `@idawrite`，避免线程问题。
- 返回 `TypedDict`（或基础类型）；返回值必须是数据拷贝，不能直接返回 IDA 迭代器。
- 危险能力（进程控制、任意代码执行）加 `@unsafe`，默认不暴露。

### 6.2 `server_generated.py` 是自动生成的

Gateway 导入时会 AST 解析 `mcp-plugin.py`，内容变化就重写：

```text
src/ida_pro_mcp/server_generated.py
```

**不要手改**。想强制重建，删除它后任意启动一次 Gateway 即可。

### 6.3 测试与检查

```bash
uv run python -m tests.test_gateway      # 不需要 IDA 的网关测试
uv run python tools/audit_formats.py     # 版本、schema、客户端配置、IDA 兼容分支审计
uv run python -m py_compile src/ida_pro_mcp/*.py
```

### 6.4 发版检查清单

版本号需要同时更新：

- `pyproject.toml` → `[project].version`
- `ida-plugin.json` → `plugin.version`
- `src/ida_pro_mcp/mcp-plugin.py` → `server_info["version"]`
- 本 README 的版本说明

---

## 7. 故障排查

### `No module named 'mcp.server.fastmcp'`

你在运行 **mcp 1.x 代码 + mcp 2.x 库**。本项目 1.7.0 已迁移到 mcp 2.x：

```python
from mcp.server.mcpserver import MCPServer
```

处理：

```bash
cd <项目目录>
uv sync
# 并确认客户端配置里的 python 是 <项目目录>/.venv/Scripts/python.exe
```

如果某处仍显示 `FastMCP`，说明跑到了旧的 pip 副本（如 `site-packages/ida_pro_mcp`）。卸载旧包或改用项目 venv。

### `No module named 'ida_pro_mcp'`

项目是 `src/` 布局且未安装进 venv。客户端配置必须带：

```json
"env": { "PYTHONPATH": "<项目目录>\\src" }
```

或手动：

```bash
PYTHONPATH=src ./.venv/Scripts/python.exe -m ida_pro_mcp.server --config
```

### IDA 里出现两个 MCP 插件 / 菜单重复

检查是否存在悬空软链：

```text
%APPDATA%\Hex-Rays\IDA Pro\plugins\mcp-plugin.py
```

如果它指向不存在的目录，删除它。只保留一种安装方式（包形式或单文件）。

### 多个旧副本互相干扰

常见副本：

```text
<IDADIR>\plugins\ida-pro-mcp-main     # 包形式，IDA 实际加载
<IDADIR>\pl\ida-pro-mcp               # git clone，不自动加载
%APPDATA%\...\plugins\mcp-plugin.py    # --install 写入的单文件
site-packages\ida_pro_mcp             # pip 副本，只影响 CLI
```

判断 IDA 实际加载的是哪一份，可在插件里执行：

```python
import sys
print({k: v.__file__ for k, v in sys.modules.items() if "mcp" in k.lower()})
```

### `/mcp` 报 `ECONNREFUSED at http://127.0.0.1:13337`

说明客户端被配置成了**直连 IDA 插件**（`"type": "http"` / `"url": "http://127.0.0.1:13337/mcp"`），而不是 stdio 网关。后果：

- IDA 没开就连接失败；
- 拿不到多数据库能力；
- 每个客户端只能连一个固定端口。

正确配置应由 `uv run ida-pro-mcp --install --no-plugin` 生成：

```json
{
  "command": "<项目目录>\\.venv\\Scripts\\python.exe",
  "args": ["-m", "ida_pro_mcp.server"],
  "env": { "PYTHONPATH": "<项目目录>\\src" },
  "timeout": 600000
}
```

改完后重启 MCP 客户端。即使 IDA 没开，网关也应正常启动并让 `check_connection()` 返回 `No IDA databases connected`。

### 工具调用超时

- Claude Code 的 `timeout` 单位是**毫秒**，大库建议 `600000`（10 分钟）。
- Cline/Roo/Kilo 的单位是**秒**，建议 `1800`。
- 反编译/xrefs 在超大库上本身就可能很慢。

### IDA 9.x API 变更

本项目已处理的已知变更：

| 旧 API | IDA 9.x 替代 |
|---|---|
| `idaapi.get_inf_structure()` | `ida_ida.inf_is_64bit()` / `inf_get_min_ea()` / `inf_get_max_ea()` |
| `ida_bytes.find_binary()` | `parse_binpat_str()` + `bin_search()`（或 `find_bytes()`） |
| `ida_struct` 模块 | 用 `ida_typeinf` / `tinfo_t` |
| `ida_gdl.BasicBlock.nsucc()/npred()/succ()/pred()` | `BasicBlock.succs()` / `preds()` 迭代器 |
| `parse_decl` | `parse_decls` / `tinfo_t(text, None, flags)` |

新增/修改工具后，建议对照本机 IDA 的存根确认 API：

```text
<IDADIR>/python/ida_*.py     # 当前 IDA 的权威签名与 docstring
<IDADIR>/docs/release-notes/ # 版本变更
```

---

## 8. 版本与血统

```text
mrexodia/ida-pro-mcp  →  icryo/ida-pro-mcp (v1.6.0 功能线)  →  本项目 (当前分支)
```

本分支在 1.6.0 基础上：

- 迁移到 `mcp` 2.x `MCPServer`
- 修复 IDA 9.5 `BasicBlock` API 兼容
- 多数据库 Gateway（实例注册表、并发转发、headless 进程池）
- vtable / 虚函数工具（扫描、建 vftable 类型、重命名、xref）
- MCP 协议版本支持到 `2025-11-25`
- 重写文档与安装/排障说明

上游 `mrexodia/ida-pro-mcp` 已转向新的 `ida-mcp` 方向；本分支保留 1.6.0 的工具集合与多库网关设计。

## 9. License

MIT。原始架构来自 [mrexodia/ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp)。
