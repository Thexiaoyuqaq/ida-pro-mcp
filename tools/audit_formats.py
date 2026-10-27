"""Format-consistency audit for ida-pro-mcp.

Scans the source tree for the four classes of "format drift" that accumulate
across releases:

  1. Version / protocol identifiers scattered across packaging files
  2. MCP tool parameter schemas (defaults marked required, type downgrades)
  3. Per-client MCP config shapes (key names, timeout units, file format)
  4. IDA API version-compatibility branches

Run: python tools/audit_formats.py   (from the repo root)
"""

from __future__ import annotations

import ast
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "src", "ida_pro_mcp")


def section(title: str) -> None:
    print(f"\n{'=' * 70}\n{title}\n{'=' * 70}")


def read(path: str) -> str:
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


# ---------------------------------------------------------------------------
# 1. Version / protocol identifiers
# ---------------------------------------------------------------------------

def audit_versions() -> list[str]:
    section("1. VERSION / PROTOCOL IDENTIFIERS")
    found: list[tuple[str, str, str]] = []

    pyproject = read(os.path.join(ROOT, "pyproject.toml"))
    m = re.search(r'^version\s*=\s*"([^"]+)"', pyproject, re.M)
    if m:
        found.append(("pyproject.toml", "package version", m.group(1)))

    plugin_json = json.loads(read(os.path.join(ROOT, "ida-plugin.json")))
    found.append(("ida-plugin.json", "plugin version",
                  plugin_json["plugin"]["version"]))

    plugin_py = read(os.path.join(SRC, "mcp-plugin.py"))
    m = re.search(r'"version":\s*"([^"]+)"', plugin_py)
    if m:
        found.append(("mcp-plugin.py server_info", "serverInfo version", m.group(1)))
    m = re.search(r'"protocolVersion":\s*"([^"]+)"', plugin_py)
    if m:
        found.append(("mcp-plugin.py handle_initialize", "MCP protocol version", m.group(1)))

    readme = read(os.path.join(ROOT, "README.md"))
    m = re.search(r"New in (v[\d.]+)", readme)
    if m:
        found.append(("README.md", "featured version", m.group(1)))

    m = re.search(r'MCPServer\("([^"]+)"', read(os.path.join(SRC, "server.py")))
    if m:
        found.append(("server.py", "gateway MCPServer name", m.group(1)))
    m = re.search(r'MCPServer\("([^"]+)"', read(os.path.join(SRC, "idalib_server.py")))
    if m:
        found.append(("idalib_server.py", "idalib MCPServer name", m.group(1)))

    for origin, what, value in found:
        print(f"  {origin:45s} {what:24s} = {value}")

    pkg_versions = {v for _, w, v in found if w in ("package version", "plugin version", "serverInfo version")}
    if len(pkg_versions) > 1:
        print(f"\n  [!] INCONSISTENT version numbers: {sorted(pkg_versions)}")
    else:
        print(f"\n  [ok] version numbers consistent: {pkg_versions}")

    protocols = {v for _, w, v in found if w == "MCP protocol version"}
    for p in sorted(protocols):
        print(f"  [i] MCP protocol pinned to {p} (verify still current in mcp lib)")

    return [(o, w, v) for o, w, v in found]


# ---------------------------------------------------------------------------
# 2. Tool parameter schemas
# ---------------------------------------------------------------------------

JSON_TYPE = {"int": "integer", "float": "number", "bool": "boolean", "str": "string"}


def _json_type(annotation: ast.expr) -> str:
    """Replicates generate_tool_schema's type mapping (mcp-plugin.py:265).

    Unwraps Annotated[..., desc], Optional[X] / Union[X, None], and plain
    X | None (3.10+ syntax) so the reported type matches what the runtime
    actually emits in the MCP schema.
    """
    if isinstance(annotation, ast.Subscript):
        value = annotation.value
        if isinstance(value, ast.Name) and value.id == "Annotated":
            # Annotated[Inner, "description"] -> recurse on Inner
            inner = annotation.slice.elts[0] if isinstance(annotation.slice, ast.Tuple) else annotation.slice
            return _json_type(inner)
        if isinstance(value, ast.Name) and value.id in ("Optional", "Union"):
            # Optional[X] / Union[X, None] -> recurse on first non-None arg
            args = annotation.slice.elts if isinstance(annotation.slice, ast.Tuple) else [annotation.slice]
            non_none = [a for a in args if not (isinstance(a, ast.Constant) and a.value is None)]
            if non_none:
                return _json_type(non_none[0])
            return "string"
    if isinstance(annotation, ast.BinOp) and isinstance(annotation.op, ast.BitOr):
        # X | None (3.10+ union syntax, parser produces BinOp)
        left = _json_type(annotation.left)
        if left != "string":
            return left
        right = _json_type(annotation.right)
        if right != "string":
            return right
        return "string"
    if isinstance(annotation, ast.Name):
        return JSON_TYPE.get(annotation.id, "string")
    if isinstance(annotation, ast.Constant) and isinstance(annotation.value, str):
        return "string"
    return "string"


def _is_optional_or_plain_str(ann_src: str) -> bool:
    """Return True when the annotation represents an (optional) string, so the
    "downgraded to string" flag is a real issue rather than a false positive.

    Recognizes:
      str
      Annotated[str, "desc"]
      Annotated[Optional[str], "desc"]
      Annotated[Union[str, None], "desc"]
      Optional[str]
      Union[str, None]
    Does NOT recognize mixed unions like Union[str, int].
    """
    if ann_src in ("str", "<none>"):
        return True

    # Annotated[X, "desc"] -> recurse on X
    if ann_src.startswith("Annotated["):
        inner = ann_src[len("Annotated["):-1]  # strip leading "Annotated[" and trailing "]"
        # Find the first top-level comma to separate X from the description
        # depth starts at 0 since we already stripped the outer brackets
        depth = 0
        comma_pos = -1
        for i, ch in enumerate(inner):
            if ch in "[(":
                depth += 1
            elif ch in ")]":
                depth -= 1
            elif ch == "," and depth == 0:
                comma_pos = i
                break
        if comma_pos != -1:
            inner = inner[:comma_pos].strip()
        # Recurse on the inner type
        return _is_optional_or_plain_str(inner)

    # Optional[X] / Union[X, Y, ...]
    if ann_src.startswith("Optional["):
        inner = ann_src[len("Optional["):-1]
        return _is_optional_or_plain_str(inner.strip())

    if ann_src.startswith("Union["):
        inner = ann_src[len("Union["):-1]
        # Split by top-level commas (respecting nesting)
        depth = 0
        parts = []
        current = ""
        for ch in inner:
            if ch in "[(":
                depth += 1
                current += ch
            elif ch in ")]":
                depth -= 1
                current += ch
            elif ch == "," and depth == 0:
                parts.append(current.strip())
                current = ""
            else:
                current += ch
        if current:
            parts.append(current.strip())
        # Must contain str and nothing but str/None
        non_none = [p for p in parts if p != "None"]
        return len(non_none) == 1 and non_none[0] == "str"

    return False


def audit_schemas() -> list[dict]:
    section("2. TOOL PARAMETER SCHEMAS (@jsonrpc functions in mcp-plugin.py)")
    tree = ast.parse(read(os.path.join(SRC, "mcp-plugin.py")))

    functions: list[dict] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if not any(isinstance(d, ast.Name) and d.id == "jsonrpc" for d in node.decorator_list):
            continue
        args = node.args
        defaults = [None] * (len(args.args) - len(args.defaults)) + list(args.defaults)
        params = []
        for arg, default in zip(args.args, defaults):
            ann = arg.annotation
            ann_src = ast.unparse(ann) if ann else "<none>"
            params.append({
                "name": arg.arg,
                "annotation": ann_src,
                "json_type": _json_type(ann) if ann else "string",
                "has_default": default is not None,
                "default": ast.unparse(default) if default is not None else None,
            })
        functions.append({"name": node.name, "params": params})

    # Parameters with defaults are intentionally optional in the runtime schema
    # (generate_tool_schema marks them non-required), so report them only
    # informationally.
    defaulted = []
    type_issues = []
    for fn in functions:
        for p in fn["params"]:
            if p["has_default"]:
                defaulted.append((fn["name"], p["name"], p["default"]))
            if p["json_type"] == "string" and not _is_optional_or_plain_str(p["annotation"]):
                type_issues.append((fn["name"], p["name"], p["annotation"], p["json_type"]))

    print(f"  scanned {len(functions)} @jsonrpc functions, "
          f"{sum(len(f['params']) for f in functions)} parameters total\n")

    if defaulted:
        print("  [i] parameters with defaults — marked OPTIONAL in the runtime schema (verified by tests):")
        for fn, name, default in defaulted:
            print(f"      {fn}({name} = {default})")
    else:
        print("  [ok] no defaulted parameters found")

    print()
    if type_issues:
        print("  [!] non-str annotations downgraded to JSON type \"string\":")
        for fn, name, ann, jt in type_issues:
            print(f"      {fn}({name}: {ann}) -> schema type {jt}")
    else:
        print("  [ok] no non-string types downgraded")

    return functions


# ---------------------------------------------------------------------------
# 3. Per-client MCP config shapes
# ---------------------------------------------------------------------------

def audit_client_configs() -> None:
    section("3. PER-CLIENT MCP CONFIG (server.py install_mcp_servers)")
    server_src = read(os.path.join(SRC, "server.py"))

    entry_fn = re.search(r"def _gateway_server_entry\(.*?\n(?=\ndef |\n@)", server_src, re.S)
    body = entry_fn.group(0) if entry_fn else server_src
    m = re.search(r'entry\["timeout"\]\s*=\s*(\d+)\s*#\s*(.*)', body)
    claude_ms = m.group(1) if m else "?"
    m = re.search(r'entry\["timeout"\]\s*=\s*(\d+)\s*(?:#\s*(.*))?', body[body.find("else"):])
    cline_s = m.group(1) if m else "?"

    print(f"  Claude Code timeout : {claude_ms:>6}  (milliseconds)")
    print(f"  Cline/Roo/Kilo timeout: {cline_s:>6}  (seconds)")
    print("  Claude Code keys: permissions.allow (autoApprove/alwaysAllow ignored)")
    print("  Cline/Roo/Kilo keys: autoApprove, alwaysAllow, disabled")
    print()

    # config file table
    configs_block = re.search(r"configs\s*=\s*\{(.*?)\n        \}", server_src, re.S)
    rows = []
    if configs_block:
        # Entries look like: "Name": (os.path.join(...), "filename.json"),
        # The config filename is the last .json/.toml string in the tuple.
        block = configs_block.group(1)
        for m in re.finditer(r'"([^"]+)":\s*\(.*?"([^"]+\.(?:json|toml))"\s*\)', block, re.S):
            name, fname = m.group(1), m.group(2)
            rows.append((name, fname, "TOML" if fname.endswith(".toml") else "JSON"))
    widths = [max(len(r[i]) for r in rows) + 2 for i in range(3)]
    print(f"  {'client':<{widths[0]}} {'config file':<{widths[1]}} format")
    print(f"  {'-' * widths[0]} {'-' * widths[1]} {'-' * 6}")
    for name, fname, fmt in sorted(rows):
        print(f"  {name:<{widths[0]}} {fname:<{widths[1]}} {fmt}")

    formats = {fmt for _, _, fmt in rows}
    print(f"\n  [i] {len(rows)} clients, {len(formats)} file formats: {sorted(formats)}")

    # platform branches
    platforms = re.findall(r'elif sys\.platform == "(\w+)"|if sys\.platform == "(\w+)"', server_src)
    print(f"  [i] platform config blocks: {sorted({p for a in platforms for p in a if p})}")


# ---------------------------------------------------------------------------
# 4. IDA API version-compat branches
# ---------------------------------------------------------------------------

def audit_ida_compat() -> None:
    section("4. IDA API VERSION-COMPATIBILITY BRANCHES")
    plugin_src = read(os.path.join(SRC, "mcp-plugin.py"))
    idalib_src = read(os.path.join(SRC, "idalib_server.py"))

    patterns = [
        (r"ida_major,\s*ida_minor\s*=.*", "kernel version probe"),
        (r"except AttributeError", "API-absent fallback (AttributeError)"),
        (r"except Exception.*\n.*parse_decl", "tinfo_t constructor fallback"),
        (r"if ida_major >= 9", "explicit IDA >=9 branch"),
        (r"get_inf_structure\(\)", "legacy inf structure (removed in IDA 9)"),
        (r"inf_get_(?:omin|omax)_ea\(\)|inf_is_64bit\(\)", "new inf_* API (IDA 9)"),
        (r"fn\.get_name\(\)", "func_t.get_name (newer)"),
        (r"fn\.get_prototype\(\)", "func_t.get_prototype (newer)"),
        (r"import ida as idapro", "idalib module: ida (9.0+)"),
        (r"import idapro", "idalib module: idapro (8.x)"),
        (r"import ida_struct", "ida_struct (lazy, removed IDA 9)"),
    ]

    hits: list[tuple[str, str, str]] = []
    for pattern, desc in patterns:
        for fname, text in (("mcp-plugin.py", plugin_src), ("idalib_server.py", idalib_src)):
            for i, line in enumerate(text.splitlines(), 1):
                if re.search(pattern, line):
                    hits.append((f"{fname}:{i}", desc, line.strip()))

    if not hits:
        print("  [ok] no compat branches found")
        return

    current: str | None = None
    for loc, desc, line in hits:
        if desc != current:
            print(f"\n  {desc}:")
            current = desc
        print(f"      {loc:<22s} {line[:90]}")

    legacy = [h for h in hits if "legacy" in h[1] or "removed" in h[1] or "8.x" in h[1] or "newer" in h[1] and False]
    print(f"\n  [i] {len(hits)} compat touchpoints across {len({h[0].split(':')[0] for h in hits})} files")


# ---------------------------------------------------------------------------

def main() -> int:
    print("ida-pro-mcp format-consistency audit")
    print(f"root: {ROOT}")
    audit_versions()
    audit_schemas()
    audit_client_configs()
    audit_ida_compat()
    section("DONE")
    print("  Review every [!] line above; [i] lines are informational.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
