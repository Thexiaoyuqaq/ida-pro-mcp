import os
import sys
import ast
import json
import time
import uuid
import shutil
import signal
import atexit
import asyncio
import argparse
import tempfile
import tomllib
import subprocess
import tomli_w
from typing import Annotated, Optional
from urllib.parse import urlparse
from glob import glob

import httpx
from pydantic import Field
from mcp.server.fastmcp import FastMCP

from ida_pro_mcp import discovery

# The log_level is necessary for Cline to work: https://github.com/jlowin/fastmcp/issues/81
mcp = FastMCP("ida-pro-mcp", log_level="ERROR")

# Gateway-native tools (not generated from mcp-plugin.py). Kept safe/auto-approved.
GATEWAY_TOOLS = [
    "list_databases",
    "use_database",
    "load_database",
    "close_database",
    "save_database",
    "get_database_status",
]

# Optional explicit target from --ida-rpc, used only as a fallback when the
# discovery registry is empty (e.g. a single manually-pointed IDA instance).
_explicit_target: "Optional[discovery.InstanceInfo]" = None

# Session-global default database id (set via use_database). A per-call `database`
# argument always overrides this.
_active_db: str = ""

# idalib worker subprocesses spawned by the headless pool: id -> Popen
_workers: "dict[str, subprocess.Popen]" = {}

# Auto-analysis and decompilation can be slow, so allow generous per-call timeouts.
_HTTP_TIMEOUT = 300.0
_http_client: "Optional[httpx.AsyncClient]" = None


def _client() -> httpx.AsyncClient:
    """Lazily create a pooled async HTTP client shared across all instances."""
    global _http_client
    if _http_client is None:
        _http_client = httpx.AsyncClient(
            timeout=httpx.Timeout(_HTTP_TIMEOUT),
            limits=httpx.Limits(max_keepalive_connections=20, max_connections=50),
        )
    return _http_client


def _discover_instances() -> "list[discovery.InstanceInfo]":
    instances = discovery.discover()
    if not instances and _explicit_target is not None:
        return [_explicit_target]
    return instances


def resolve_target(database: str) -> "discovery.InstanceInfo":
    """Pick the IDA instance for a call: explicit id/module/port > active > sole one."""
    instances = _discover_instances()
    if database:
        for inst in instances:
            if database in (inst.id, inst.module, str(inst.port)):
                return inst
        raise Exception(
            f"Database '{database}' not found. Call list_databases() to see what is available."
        )
    if _active_db:
        for inst in instances:
            if inst.id == _active_db:
                return inst
    if len(instances) == 1:
        return instances[0]
    if not instances:
        raise Exception(
            "No IDA databases available. In IDA run Edit -> Plugins -> MCP to start the "
            "server, or use load_database() for headless analysis."
        )
    listing = ", ".join(f"{i.module or i.idb_path or '?'} (id={i.id})" for i in instances)
    raise Exception(
        f"Multiple databases available: {listing}. Pass the 'database' argument or call "
        f"use_database(id) first."
    )


async def forward(target: "discovery.InstanceInfo", method: str, params: list):
    """Forward a JSON-RPC call to a specific IDA instance over the pooled client."""
    request = {
        "jsonrpc": "2.0",
        "method": method,
        "params": list(params),
        "id": uuid.uuid4().hex,  # unique per request -> no shared-counter races
    }
    url = f"http://{target.host}:{target.port}/mcp"
    try:
        response = await _client().post(
            url, json=request, headers={"Content-Type": "application/json"}
        )
        data = response.json()
    except Exception as e:
        raise Exception(
            f"Failed to reach IDA instance {target.module or target.id} at {url}: {e}"
        )

    if "error" in data:
        error = data["error"]
        pretty = f"JSON-RPC error {error['code']}: {error['message']}"
        if "data" in error:
            pretty += "\n" + str(error["data"])
        raise Exception(pretty)

    result = data.get("result")
    # NOTE: LLMs do not respond well to empty responses
    return "success" if result is None else result


async def dispatch_to_ida(method: str, database: str, *params):
    """Resolve the target database and forward the call (used by generated tools)."""
    target = resolve_target(database)
    return await forward(target, method, list(params))


@mcp.tool()
async def check_connection() -> str:
    """Check whether any IDA databases are connected"""
    instances = _discover_instances()
    if not instances:
        shortcut = "Ctrl+Option+M" if sys.platform == "darwin" else "Ctrl+Alt+M"
        return (
            f"No IDA databases connected. Run Edit -> Plugins -> MCP ({shortcut}) in IDA, "
            f"or load_database() in headless mode."
        )
    parts = [
        f"{i.module or i.idb_path or '?'} (id={i.id}, {i.kind}, port {i.port})"
        for i in instances
    ]
    return f"Connected to {len(instances)} database(s): " + "; ".join(parts)

# Code taken from https://github.com/mrexodia/ida-pro-mcp (MIT License)
class MCPVisitor(ast.NodeVisitor):
    def __init__(self):
        self.types: dict[str, ast.ClassDef] = {}
        self.functions: dict[str, ast.FunctionDef] = {}
        self.descriptions: dict[str, str] = {}
        self.unsafe: list[str] = []

    def visit_FunctionDef(self, node):
        for decorator in node.decorator_list:
            if isinstance(decorator, ast.Name):
                if decorator.id == "jsonrpc":
                    for i, arg in enumerate(node.args.args):
                        arg_name = arg.arg
                        arg_type = arg.annotation
                        if arg_type is None:
                            raise Exception(f"Missing argument type for {node.name}.{arg_name}")
                        if isinstance(arg_type, ast.Subscript):
                            assert isinstance(arg_type.value, ast.Name)
                            assert arg_type.value.id == "Annotated"
                            assert isinstance(arg_type.slice, ast.Tuple)
                            assert len(arg_type.slice.elts) == 2
                            annot_type = arg_type.slice.elts[0]
                            annot_description = arg_type.slice.elts[1]
                            assert isinstance(annot_description, ast.Constant)
                            node.args.args[i].annotation = ast.Subscript(
                                value=ast.Name(id="Annotated", ctx=ast.Load()),
                                slice=ast.Tuple(
                                    elts=[
                                    annot_type,
                                    ast.Call(
                                        func=ast.Name(id="Field", ctx=ast.Load()),
                                        args=[],
                                        keywords=[
                                        ast.keyword(
                                            arg="description",
                                            value=annot_description)])],
                                    ctx=ast.Load()),
                                ctx=ast.Load())
                        elif isinstance(arg_type, ast.Name):
                            pass
                        else:
                            raise Exception(f"Unexpected type annotation for {node.name}.{arg_name} -> {type(arg_type)}")

                    body_comment = node.body[0]
                    if isinstance(body_comment, ast.Expr) and isinstance(body_comment.value, ast.Constant):
                        new_body = [body_comment]
                        self.descriptions[node.name] = body_comment.value.value
                    else:
                        new_body = []

                    # Capture the original (forwarded) arguments before we append
                    # the injected `database` selector parameter.
                    original_args = list(node.args.args)

                    # Inject: `database: Annotated[str, Field(description=...)] = ""`
                    database_arg = ast.arg(
                        arg="database",
                        annotation=ast.Subscript(
                            value=ast.Name(id="Annotated", ctx=ast.Load()),
                            slice=ast.Tuple(
                                elts=[
                                    ast.Name(id="str", ctx=ast.Load()),
                                    ast.Call(
                                        func=ast.Name(id="Field", ctx=ast.Load()),
                                        args=[],
                                        keywords=[ast.keyword(
                                            arg="description",
                                            value=ast.Constant(value="Target database id/module/port (from list_databases). Empty uses the current or only database."))])],
                                ctx=ast.Load()),
                            ctx=ast.Load()))
                    node.args.args.append(database_arg)
                    node.args.defaults.append(ast.Constant(value=""))

                    # Body: `return await dispatch_to_ida("<name>", database, *original_args)`
                    call_args = [
                        ast.Constant(value=node.name),
                        ast.Name(id="database", ctx=ast.Load()),
                    ]
                    for arg in original_args:
                        call_args.append(ast.Name(id=arg.arg, ctx=ast.Load()))
                    new_body.append(ast.Return(
                        value=ast.Await(value=ast.Call(
                            func=ast.Name(id="dispatch_to_ida", ctx=ast.Load()),
                            args=call_args,
                            keywords=[]))))
                    decorator_list = [
                        ast.Call(
                            func=ast.Attribute(
                                value=ast.Name(id="mcp", ctx=ast.Load()),
                                attr="tool",
                                ctx=ast.Load()),
                            args=[],
                            keywords=[]
                        )
                    ]
                    node_nobody = ast.AsyncFunctionDef(node.name, node.args, new_body, decorator_list, node.returns, node.type_comment, lineno=node.lineno, col_offset=node.col_offset)
                    assert node.name not in self.functions, f"Duplicate function: {node.name}"
                    self.functions[node.name] = node_nobody
                elif decorator.id == "unsafe":
                    self.unsafe.append(node.name)

    def visit_ClassDef(self, node):
        for base in node.bases:
            if isinstance(base, ast.Name):
                if base.id == "TypedDict":
                    self.types[node.name] = node


SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
IDA_PLUGIN_PY = os.path.join(SCRIPT_DIR, "mcp-plugin.py")
GENERATED_PY = os.path.join(SCRIPT_DIR, "server_generated.py")

# NOTE: This is in the global scope on purpose
if not os.path.exists(IDA_PLUGIN_PY):
    raise RuntimeError(f"IDA plugin not found at {IDA_PLUGIN_PY} (did you move it?)")
with open(IDA_PLUGIN_PY, "r", encoding="utf-8") as f:
    code = f.read()
module = ast.parse(code, IDA_PLUGIN_PY)
visitor = MCPVisitor()
visitor.visit(module)
code = """# NOTE: This file has been automatically generated, do not modify!
# Architecture based on https://github.com/mrexodia/ida-pro-mcp (MIT License)
import sys
if sys.version_info >= (3, 12):
    from typing import Annotated, Optional, TypedDict, Generic, TypeVar, NotRequired
else:
    from typing_extensions import Annotated, Optional, TypedDict, Generic, TypeVar, NotRequired
from pydantic import Field

T = TypeVar("T")

"""
for type in visitor.types.values():
    code += ast.unparse(type)
    code += "\n\n"
for function in visitor.functions.values():
    code += ast.unparse(function)
    code += "\n\n"

try:
    if os.path.exists(GENERATED_PY):
        with open(GENERATED_PY, "rb") as f:
            existing_code_bytes = f.read()
    else:
        existing_code_bytes = b""
    code_bytes = code.encode("utf-8").replace(b"\r", b"")
    if code_bytes != existing_code_bytes:
        with open(GENERATED_PY, "wb") as f:
            f.write(code_bytes)
except:
    print(f"Failed to generate code: {GENERATED_PY}", file=sys.stderr, flush=True)

exec(compile(code, GENERATED_PY, "exec"))


# ============================================================================
# Gateway-native tools: database discovery, selection, and headless pool
# ============================================================================

def _terminate_pid(pid: int) -> None:
    """Best-effort terminate a process by pid (cross-platform, safe)."""
    if pid <= 0:
        return
    try:
        if sys.platform == "win32":
            subprocess.run(["taskkill", "/PID", str(pid), "/F", "/T"], capture_output=True)
        else:
            os.kill(pid, signal.SIGTERM)
    except Exception:
        pass


def _database_summary(inst: "discovery.InstanceInfo") -> dict:
    return {
        "id": inst.id,
        "module": inst.module,
        "path": inst.idb_path,
        "port": inst.port,
        "kind": inst.kind,
        "active": inst.id == _active_db,
    }


@mcp.tool()
def list_databases() -> list:
    """List all connected IDA databases (GUI instances and headless workers)"""
    return [_database_summary(i) for i in _discover_instances()]


@mcp.tool()
def use_database(
    database: Annotated[str, "Database id/module/port (from list_databases) to make the default"],
) -> str:
    """Select the default database for subsequent tool calls in this session"""
    global _active_db
    target = resolve_target(database)
    _active_db = target.id
    return f"Active database set to {target.module or target.id} (id={target.id}, port {target.port})"


@mcp.tool()
async def load_database(
    path: Annotated[str, "Path to the binary file or IDB to analyze"],
    run_auto_analysis: Annotated[bool, "Run automatic analysis after loading"] = True,
) -> dict:
    """Load a binary/IDB in a new headless idalib worker process (headless mode)"""
    abspath = os.path.abspath(path)
    if not os.path.exists(abspath):
        return {"success": False, "error": f"File not found: {path}"}

    # Already loaded in a headless worker? (match by path, not id)
    norm = os.path.normcase(abspath)
    for inst in _discover_instances():
        if inst.kind == "idalib" and os.path.normcase(inst.idb_path) == norm:
            return {"success": True, **_database_summary(inst), "message": "Database already loaded"}

    args = [get_python_executable(), "-m", "ida_pro_mcp.idalib_server", "--worker", abspath]
    if not run_auto_analysis:
        args.append("--no-analysis")
    proc = subprocess.Popen(args, env=os.environ.copy())

    # The worker's id depends on its (OS-assigned) port, so we can't precompute
    # it here -- instead wait for a registry entry owned by this process's pid.
    deadline = time.time() + _HTTP_TIMEOUT
    while time.time() < deadline:
        if proc.poll() is not None:
            return {"success": False, "error": f"Worker process exited early (code {proc.returncode})"}
        for inst in _discover_instances():
            if inst.pid == proc.pid:
                _workers[inst.id] = proc
                return {"success": True, **_database_summary(inst),
                        "message": f"Loaded {os.path.basename(abspath)}"}
        await asyncio.sleep(0.5)

    proc.terminate()
    return {"success": False, "error": "Timed out waiting for the worker to become ready"}


@mcp.tool()
def close_database(
    database: Annotated[str, "Database id to close (empty = current). GUI databases must be closed in IDA."] = "",
) -> dict:
    """Close a headless (idalib) database and terminate its worker process"""
    global _active_db
    target = resolve_target(database)
    if target.kind != "idalib":
        return {"success": False, "error": "Only headless (idalib) databases can be closed by the gateway. Close GUI databases inside IDA."}

    proc = _workers.pop(target.id, None)
    if proc is not None:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except Exception:
            proc.kill()
    else:
        _terminate_pid(target.pid)
    discovery.unregister(target.id)
    if _active_db == target.id:
        _active_db = ""
    return {"success": True, "message": f"Closed {target.module or target.id}"}


@mcp.tool()
async def save_database(
    database: Annotated[str, "Database id to save (empty = current)"] = "",
    path: Annotated[str, "Optional output path; empty saves to the current IDB path"] = "",
) -> dict:
    """Save a database to disk, preserving all analysis"""
    target = resolve_target(database)
    return await forward(target, "save_database", [path])


@mcp.tool()
def get_database_status() -> dict:
    """Get the status of all connected databases and the current selection"""
    instances = _discover_instances()
    return {
        "count": len(instances),
        "active": _active_db,
        "databases": [_database_summary(i) for i in instances],
    }


@atexit.register
def _cleanup_workers() -> None:
    for proc in list(_workers.values()):
        try:
            proc.terminate()
        except Exception:
            pass


MCP_FUNCTIONS = ["check_connection"] + GATEWAY_TOOLS + list(visitor.functions.keys())
UNSAFE_FUNCTIONS = visitor.unsafe
SAFE_FUNCTIONS = [f for f in MCP_FUNCTIONS if f not in UNSAFE_FUNCTIONS]

def generate_readme():
    print("README:")
    print("- `check_connection()`: Check if the IDA plugin is running.")
    def get_description(name: str):
        function = visitor.functions[name]
        signature = function.name + "("
        for i, arg in enumerate(function.args.args):
            if i > 0:
                signature += ", "
            signature += arg.arg
        signature += ")"
        description = visitor.descriptions.get(function.name, "<no description>").strip().split("\n")[0].strip()
        if description[-1] != ".":
            description += "."
        return f"- `{signature}`: {description}"
    for safe_function in SAFE_FUNCTIONS:
        if safe_function != "check_connection" and safe_function in visitor.functions:
            print(get_description(safe_function))
    print("\nUnsafe functions (`--unsafe` flag required):\n")
    for unsafe_function in UNSAFE_FUNCTIONS:
        print(get_description(unsafe_function))
    print("\nMCP Config:")
    mcp_config = {
        "mcpServers": {
            mcp.name: _gateway_server_entry(is_toml=False),
        }
    }
    print(json.dumps(mcp_config, indent=2))

def get_python_executable():
    """Get the path to the Python executable"""
    venv = os.environ.get("VIRTUAL_ENV")
    if venv:
        if sys.platform == "win32":
            python = os.path.join(venv, "Scripts", "python.exe")
        else:
            python = os.path.join(venv, "bin", "python3")
        if os.path.exists(python):
            return python

    for path in sys.path:
        if sys.platform == "win32":
            path = path.replace("/", "\\")

        split = path.split(os.sep)
        if split[-1].endswith(".zip"):
            path = os.path.dirname(path)
            if sys.platform == "win32":
                python_executable = os.path.join(path, "python.exe")
            else:
                python_executable = os.path.join(path, "..", "bin", "python3")
            python_executable = os.path.abspath(python_executable)

            if os.path.exists(python_executable):
                return python_executable
    return sys.executable

def copy_python_env(env: dict[str, str]):
    # Reference: https://docs.python.org/3/using/cmdline.html#environment-variables
    python_vars = [
        "PYTHONHOME",
        "PYTHONPATH",
        "PYTHONSAFEPATH",
        "PYTHONPLATLIBDIR",
        "PYTHONPYCACHEPREFIX",
        "PYTHONNOUSERSITE",
        "PYTHONUSERBASE",
    ]
    # MCP servers are run without inheriting the environment, so we need to forward
    # the environment variables that affect Python's dependency resolution by hand.
    # Issue: https://github.com/mrexodia/ida-pro-mcp/issues/111
    result = False
    for var in python_vars:
        value = os.environ.get(var)
        if value:
            result = True
            env[var] = value
    return result

def _interpreter_works(python_exe: str, src_dir: str) -> bool:
    """Check that an interpreter actually starts and can import the gateway + deps."""
    try:
        env = os.environ.copy()
        existing = env.get("PYTHONPATH", "")
        env["PYTHONPATH"] = os.pathsep.join([src_dir] + ([existing] if existing else []))
        result = subprocess.run(
            [python_exe, "-c", "import httpx, mcp, pydantic, ida_pro_mcp"],
            env=env, capture_output=True, timeout=30,
        )
        return result.returncode == 0
    except Exception:
        return False


def _resolve_gateway_python(src_dir: str) -> str:
    """Pick a working interpreter for the gateway.

    `sys.executable` can be a broken/uv-managed venv launcher (e.g. a venv missing
    pyvenv.cfg), which would make the client fail to spawn the server. Validate
    candidates and fall back to the base interpreter or one on PATH.
    """
    candidates = [sys.executable, getattr(sys, "_base_executable", None)]
    candidates += [shutil.which("python"), shutil.which("python3")]
    seen: set[str] = set()
    for python_exe in candidates:
        if not python_exe or python_exe in seen:
            continue
        seen.add(python_exe)
        if _interpreter_works(python_exe, src_dir):
            return python_exe
    return sys.executable  # last resort; nothing validated


def _gateway_server_entry(is_toml: bool, client: str = "") -> dict:
    """Config entry pointing the MCP client at this gateway (a single stable stdio entry).

    Pins PYTHONPATH to the real on-disk source directory and uses a validated
    interpreter so the entry works whether or not the package was pip-installed.

    `client` is the human-readable client name (keys of the `configs` dict in
    install_mcp_servers). It matters because the per-server `timeout` field is
    interpreted in different units by different clients.
    """
    src_dir = os.path.dirname(SCRIPT_DIR)  # .../src (parent of the ida_pro_mcp package)
    entry: dict = {
        "command": _resolve_gateway_python(src_dir),
        "args": ["-m", "ida_pro_mcp.server"],
    }
    server_env: dict[str, str] = {}
    copy_python_env(server_env)
    existing_pp = server_env.get("PYTHONPATH", os.environ.get("PYTHONPATH", ""))
    parts = [src_dir]
    for p in existing_pp.split(os.pathsep):
        if p and os.path.normcase(p) != os.path.normcase(src_dir):
            parts.append(p)
    server_env["PYTHONPATH"] = os.pathsep.join(parts)
    entry["env"] = server_env
    if not is_toml:
        if client == "Claude Code":
            # Claude Code reads mcpServers."timeout" in MILLISECONDS and treats it as
            # the per-tool-call wall-clock limit (overriding MCP_TOOL_TIMEOUT). Writing
            # 1800 here would mean 1.8s and kill any slow call (xrefs, decompile, ...).
            # It also uses its own permission system (permissions.allow in settings.json),
            # so the Cline-style autoApprove/alwaysAllow/disabled keys are ignored.
            entry["timeout"] = 600000  # 10 minutes, in milliseconds
        else:
            # Cline / Roo Code / Kilo Code convention: "timeout" is in SECONDS, plus
            # their own approval keys. Other JSON clients ignore these harmlessly.
            entry["timeout"] = 1800
            entry["disabled"] = False
            entry["autoApprove"] = SAFE_FUNCTIONS
            entry["alwaysAllow"] = SAFE_FUNCTIONS
    return entry


def print_mcp_config():
    print(json.dumps({"mcpServers": {mcp.name: _gateway_server_entry(is_toml=False)}}, indent=2))

def install_mcp_servers(*, uninstall=False, quiet=False, env={}):
    if sys.platform == "win32":
        configs = {
            "Cline": (os.path.join(os.getenv("APPDATA", ""), "Code", "User", "globalStorage", "saoudrizwan.claude-dev", "settings"), "cline_mcp_settings.json"),
            "Roo Code": (os.path.join(os.getenv("APPDATA", ""), "Code", "User", "globalStorage", "rooveterinaryinc.roo-cline", "settings"), "mcp_settings.json"),
            "Kilo Code": (os.path.join(os.getenv("APPDATA", ""), "Code", "User", "globalStorage", "kilocode.kilo-code", "settings"), "mcp_settings.json"),
            "Claude": (os.path.join(os.getenv("APPDATA", ""), "Claude"), "claude_desktop_config.json"),
            "Cursor": (os.path.join(os.path.expanduser("~"), ".cursor"), "mcp.json"),
            "Windsurf": (os.path.join(os.path.expanduser("~"), ".codeium", "windsurf"), "mcp_config.json"),
            "Claude Code": (os.path.join(os.path.expanduser("~")), ".claude.json"),
            "LM Studio": (os.path.join(os.path.expanduser("~"), ".lmstudio"), "mcp.json"),
            "Codex": (os.path.join(os.path.expanduser("~"), ".codex"), "config.toml"),
        }
    elif sys.platform == "darwin":
        configs = {
            "Cline": (os.path.join(os.path.expanduser("~"), "Library", "Application Support", "Code", "User", "globalStorage", "saoudrizwan.claude-dev", "settings"), "cline_mcp_settings.json"),
            "Roo Code": (os.path.join(os.path.expanduser("~"), "Library", "Application Support", "Code", "User", "globalStorage", "rooveterinaryinc.roo-cline", "settings"), "mcp_settings.json"),
            "Kilo Code": (os.path.join(os.path.expanduser("~"), "Library", "Application Support", "Code", "User", "globalStorage", "kilocode.kilo-code", "settings"), "mcp_settings.json"),
            "Claude": (os.path.join(os.path.expanduser("~"), "Library", "Application Support", "Claude"), "claude_desktop_config.json"),
            "Cursor": (os.path.join(os.path.expanduser("~"), ".cursor"), "mcp.json"),
            "Windsurf": (os.path.join(os.path.expanduser("~"), ".codeium", "windsurf"), "mcp_config.json"),
            "Claude Code": (os.path.join(os.path.expanduser("~")), ".claude.json"),
            "LM Studio": (os.path.join(os.path.expanduser("~"), ".lmstudio"), "mcp.json"),
            "Codex": (os.path.join(os.path.expanduser("~"), ".codex"), "config.toml"),
        }
    elif sys.platform == "linux":
        configs = {
            "Cline": (os.path.join(os.path.expanduser("~"), ".config", "Code", "User", "globalStorage", "saoudrizwan.claude-dev", "settings"), "cline_mcp_settings.json"),
            "Roo Code": (os.path.join(os.path.expanduser("~"), ".config", "Code", "User", "globalStorage", "rooveterinaryinc.roo-cline", "settings"), "mcp_settings.json"),
            "Kilo Code": (os.path.join(os.path.expanduser("~"), ".config", "Code", "User", "globalStorage", "kilocode.kilo-code", "settings"), "mcp_settings.json"),
            # Claude not supported on Linux
            "Cursor": (os.path.join(os.path.expanduser("~"), ".cursor"), "mcp.json"),
            "Windsurf": (os.path.join(os.path.expanduser("~"), ".codeium", "windsurf"), "mcp_config.json"),
            "Claude Code": (os.path.join(os.path.expanduser("~")), ".claude.json"),
            "LM Studio": (os.path.join(os.path.expanduser("~"), ".lmstudio"), "mcp.json"),
            "Codex": (os.path.join(os.path.expanduser("~"), ".codex"), "config.toml"),
        }
    else:
        print(f"Unsupported platform: {sys.platform}")
        return

    installed = 0
    for name, (config_dir, config_file) in configs.items():
        config_path = os.path.join(config_dir, config_file)
        is_toml = config_file.endswith(".toml")

        if not os.path.exists(config_dir):
            action = "uninstall" if uninstall else "installation"
            if not quiet:
                print(f"Skipping {name} {action}\n  Config: {config_path} (not found)")
            continue

        # Read existing config
        if not os.path.exists(config_path):
            config = {}
        else:
            with open(config_path, "rb" if is_toml else "r", encoding=None if is_toml else "utf-8") as f:
                if is_toml:
                    data = f.read()
                    if len(data) == 0:
                        config = {}
                    else:
                        try:
                            config = tomllib.loads(data.decode("utf-8"))
                        except tomllib.TOMLDecodeError:
                            if not quiet:
                                print(f"Skipping {name} uninstall\n  Config: {config_path} (invalid TOML)")
                            continue
                else:
                    data = f.read().strip()
                    if len(data) == 0:
                        config = {}
                    else:
                        try:
                            config = json.loads(data)
                        except json.decoder.JSONDecodeError:
                            if not quiet:
                                print(f"Skipping {name} uninstall\n  Config: {config_path} (invalid JSON)")
                            continue

        # Handle TOML vs JSON structure
        if is_toml:
            if "mcp_servers" not in config:
                config["mcp_servers"] = {}
            mcp_servers = config["mcp_servers"]
        else:
            if "mcpServers" not in config:
                config["mcpServers"] = {}
            mcp_servers = config["mcpServers"]

        # Migrate old name
        old_name = "github.com/mrexodia/ida-pro-mcp"
        if old_name in mcp_servers:
            mcp_servers[mcp.name] = mcp_servers[old_name]
            del mcp_servers[old_name]

        if uninstall:
            if mcp.name not in mcp_servers:
                if not quiet:
                    print(f"Skipping {name} uninstall\n  Config: {config_path} (not installed)")
                continue
            del mcp_servers[mcp.name]
        else:
            mcp_servers[mcp.name] = _gateway_server_entry(is_toml=is_toml, client=name)

        # Atomic write: temp file + rename
        suffix = ".toml" if is_toml else ".json"
        fd, temp_path = tempfile.mkstemp(dir=config_dir, prefix=".tmp_", suffix=suffix, text=True)
        try:
            with os.fdopen(fd, "wb" if is_toml else "w", encoding=None if is_toml else "utf-8") as f:
                if is_toml:
                    f.write(tomli_w.dumps(config).encode("utf-8"))
                else:
                    json.dump(config, f, indent=2)
            os.replace(temp_path, config_path)
        except:
            os.unlink(temp_path)
            raise

        if not quiet:
            action = "Uninstalled" if uninstall else "Installed"
            print(f"{action} {name} MCP server (restart required)\n  Config: {config_path}")
        installed += 1
    if not uninstall and installed == 0:
        print("No MCP servers installed. For unsupported MCP clients, use the following config:\n")
        print_mcp_config()

def install_ida_plugin(*, uninstall: bool = False, quiet: bool = False, allow_ida_free: bool = False):
    if sys.platform == "win32":
        ida_folder = os.path.join(os.getenv("APPDATA"), "Hex-Rays", "IDA Pro")
    else:
        ida_folder = os.path.join(os.path.expanduser("~"), ".idapro")
    if not allow_ida_free:
        free_licenses = glob(os.path.join(ida_folder, "idafree_*.hexlic"))
        if len(free_licenses) > 0:
            print("IDA Free does not support plugins and cannot be used. Purchase and install IDA Pro instead.")
            sys.exit(1)
    ida_plugin_folder = os.path.join(ida_folder, "plugins")
    plugin_destination = os.path.join(ida_plugin_folder, "mcp-plugin.py")
    if uninstall:
        if not os.path.exists(plugin_destination):
            print(f"Skipping IDA plugin uninstall\n  Path: {plugin_destination} (not found)")
            return
        os.remove(plugin_destination)
        if not quiet:
            print(f"Uninstalled IDA plugin\n  Path: {plugin_destination}")
    else:
        # Create IDA plugins folder
        if not os.path.exists(ida_plugin_folder):
            os.makedirs(ida_plugin_folder)

        # Skip if symlink already up to date
        realpath = os.path.realpath(plugin_destination)
        if realpath == IDA_PLUGIN_PY:
            if not quiet:
                print(f"Skipping IDA plugin installation (symlink up to date)\n  Plugin: {realpath}")
        else:
            # Remove existing plugin
            if os.path.lexists(plugin_destination):
                os.remove(plugin_destination)

            # Symlink or copy the plugin
            try:
                os.symlink(IDA_PLUGIN_PY, plugin_destination)
            except OSError:
                shutil.copy(IDA_PLUGIN_PY, plugin_destination)

            if not quiet:
                print(f"Installed IDA Pro plugin (IDA restart required)\n  Plugin: {plugin_destination}")

def main():
    global _explicit_target
    parser = argparse.ArgumentParser(description="IDA Pro MCP Server")
    parser.add_argument("--install", action="store_true", help="Install the MCP Server and IDA plugin")
    parser.add_argument("--uninstall", action="store_true", help="Uninstall the MCP Server and IDA plugin")
    parser.add_argument("--allow-ida-free", action="store_true", help="Allow installation despite IDA Free being installed")
    parser.add_argument("--generate-docs", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--install-plugin", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--transport", type=str, default="stdio", help="MCP transport protocol to use (stdio or http://127.0.0.1:8744)")
    parser.add_argument("--ida-rpc", type=str, default=None, help="Fallback IDA RPC server used only when the discovery registry is empty (e.g. http://127.0.0.1:13337)")
    parser.add_argument("--unsafe", action="store_true", help="Enable unsafe functions (DANGEROUS)")
    parser.add_argument("--config", action="store_true", help="Generate MCP config JSON")
    args = parser.parse_args()

    if args.install and args.uninstall:
        print("Cannot install and uninstall at the same time")
        return

    if args.install:
        install_ida_plugin(allow_ida_free=args.allow_ida_free)
        install_mcp_servers()
        return

    if args.uninstall:
        install_ida_plugin(uninstall=True, allow_ida_free=args.allow_ida_free)
        install_mcp_servers(uninstall=True)
        return

    # NOTE: Developers can use this to generate the README
    if args.generate_docs:
        generate_readme()
        return

    # NOTE: This is silent for automated Cline installations
    if args.install_plugin:
        install_ida_plugin(quiet=True, allow_ida_free=args.allow_ida_free)

    if args.config:
        print_mcp_config()
        return

    # Parse optional fallback IDA RPC server (used only when the registry is empty)
    if args.ida_rpc:
        ida_rpc = urlparse(args.ida_rpc)
        if ida_rpc.hostname is None or ida_rpc.port is None:
            raise Exception(f"Invalid IDA RPC server: {args.ida_rpc}")
        _explicit_target = discovery.InstanceInfo(
            id="explicit",
            host=ida_rpc.hostname,
            port=ida_rpc.port,
            idb_path="",
            module="(explicit)",
            pid=0,
            kind="gui",
            started_at=time.time(),
            heartbeat=0.0,  # 0 => never pruned by heartbeat
        )

    # Remove unsafe tools
    if not args.unsafe:
        mcp_tools = mcp._tool_manager._tools
        for unsafe in UNSAFE_FUNCTIONS:
            if unsafe in mcp_tools:
                del mcp_tools[unsafe]

    try:
        if args.transport == "stdio":
            mcp.run(transport="stdio")
        else:
            url = urlparse(args.transport)
            if url.hostname is None or url.port is None:
                raise Exception(f"Invalid transport URL: {args.transport}")
            mcp.settings.host = url.hostname
            mcp.settings.port = url.port
            # NOTE: npx @modelcontextprotocol/inspector for debugging
            print(f"MCP Server availabile at http://{mcp.settings.host}:{mcp.settings.port}/sse")
            mcp.settings.log_level = "INFO"
            mcp.run(transport="sse")
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    main()
