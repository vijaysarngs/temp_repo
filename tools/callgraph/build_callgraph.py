#!/usr/bin/env python3
"""Build an interactive function call graph for this repository.

Statically scans every Python file (via ``ast``) and every JS/JSX file
(via a light tokenizer) and writes a single self-contained HTML viewer.

    python tools/callgraph/build_callgraph.py
    python tools/callgraph/build_callgraph.py --root . --out tools/callgraph/callgraph.html

Edge kinds
    call      direct call that resolved to a project function
    dispatch  ``self.m()`` that may land on a subclass override of ``m``
    inferred  ``obj.m()`` where obj's type is unknown but ``m`` is a unique project method name
    ref       function passed around without being called (callbacks, graph nodes, Thread targets)
    http      UI ``fetch('/api/...')`` matched to the FastAPI route that serves it
"""
from __future__ import annotations

import argparse
import ast
import json
import os
import re
from collections import defaultdict
from datetime import datetime
from pathlib import Path

SKIP_DIRS = {".git", ".venv", "venv", "env", "node_modules", "__pycache__", "site-packages",
             "dist", "build", ".pytest_cache", ".mypy_cache", ".idea", ".vscode"}
JS_EXT = {".js", ".jsx", ".ts", ".tsx", ".mjs"}
# Method names too generic to guess a target from when the receiver type is unknown.
GENERIC_METHODS = {"get", "set", "run", "main", "close", "open", "read", "write", "update", "append",
                   "items", "keys", "values", "format", "join", "split", "strip", "copy", "load",
                   "dump", "dumps", "loads", "send", "start", "stop", "add", "remove", "pop", "call",
                   "invoke", "search", "fetch", "parse", "validate", "save", "lookup", "build", "find",
                   "match", "render", "reset", "clear", "count", "index", "sort", "encode", "decode"}
ROUTE_DECORATOR = re.compile(r"^(?:\w+)\.(get|post|put|patch|delete|websocket|api_route|route)$")


def discover(root: Path, exclude=()):
    py, js = [], []
    excluded = {(root / e).resolve() for e in exclude}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")
                             and Path(dirpath, d).resolve() not in excluded)
        for name in filenames:
            path = Path(dirpath, name)
            if name.endswith(".py"):
                py.append(path)
            elif path.suffix in JS_EXT and not re.search(r"\.(config|min)\.", name):
                js.append(path)
    return sorted(py), sorted(js)


def area_of(rel: str) -> str:
    """Coarse grouping used for colouring: first directory that says something."""
    parts = rel.split("/")
    if len(parts) == 1:
        return "root scripts"
    if "tests" in parts or "tests_related_files" in parts:
        return "tests"
    skip = {"src", "aegis-cve-evidence"}
    for part in parts[:-1]:
        if part not in skip:
            return part
    return parts[0]


def is_test(rel: str, name: str) -> bool:
    base = rel.rsplit("/", 1)[-1]
    return ("/tests/" in f"/{rel}" or "tests_related_files" in rel or base.startswith("test_")
            or name.split(".")[-1].startswith("test_"))


class Graph:
    def __init__(self):
        self.nodes: dict[str, dict] = {}
        self.edges: dict[tuple[str, str, str], list[int]] = defaultdict(list)

    def add_edge(self, src, dst, kind, line):
        if src == dst and kind != "call":
            return
        lines = self.edges[(src, dst, kind)]
        if line not in lines:
            lines.append(line)


# ----------------------------------------------------------------------------- Python

class ClassInfo:
    def __init__(self, module, qual, node):
        self.module, self.qual, self.node = module, qual, node
        self.methods: dict[str, str] = {}
        self.attr_types: dict[str, tuple] = {}
        self.bases: list[tuple] | None = None


class PyModule:
    def __init__(self, rel, tree, source):
        self.rel, self.tree, self.source = rel, tree, source
        self.is_package = rel.endswith("__init__.py")
        self.imports: dict[str, tuple] = {}
        self.funcs: dict[str, str] = {}       # top-level function name -> node id
        self.classes: dict[str, ClassInfo] = {}  # qualname -> info
        self.aliases: dict[str, ast.expr] = {}   # module-level  NAME = other_name


class PyAnalyzer:
    def __init__(self, root: Path, files: list[Path], graph: Graph):
        self.root, self.graph = root, graph
        self.modules: dict[str, PyModule] = {}
        self.by_suffix: dict[str, list[str]] = defaultdict(list)
        self.method_names: dict[str, list[str]] = defaultdict(list)
        self.subclasses: dict[tuple, list[tuple]] = defaultdict(list)
        self.routes: list[tuple[str, str, str]] = []   # (method, path, node id)
        self.parse_errors: list[str] = []
        for path in files:
            rel = path.relative_to(root).as_posix()
            source = path.read_text(encoding="utf-8", errors="replace")
            try:
                tree = ast.parse(source, filename=rel)
            except SyntaxError as exc:
                self.parse_errors.append(f"{rel}: {exc.msg} (line {exc.lineno})")
                continue
            self.modules[rel] = PyModule(rel, tree, source)
            parts = rel[:-3].split("/")
            if parts[-1] == "__init__":
                parts = parts[:-1]
            for i in range(len(parts)):
                self.by_suffix[".".join(parts[i:])].append(rel)

    # -- module lookup ---------------------------------------------------------
    def find_module(self, dotted: str, near: str) -> str | None:
        cands = self.by_suffix.get(dotted, [])
        if not cands:
            return None
        here = near.split("/")

        def score(cand):
            shared = 0
            for a, b in zip(cand.split("/"), here):
                if a != b:
                    break
                shared += 1
            return shared, -len(cand)
        return max(cands, key=score)

    def relative_base(self, rel: str, level: int) -> list[str]:
        parts = rel.split("/")[:-1]          # package directory of this module
        return parts[: len(parts) - (level - 1)] if level > 1 else parts

    def module_from_parts(self, parts: list[str]) -> str | None:
        stem = "/".join(parts)
        for cand in (f"{stem}.py", f"{stem}/__init__.py"):
            if cand in self.modules:
                return cand
        return None

    # -- pass 1: imports, definitions -----------------------------------------
    def collect(self):
        for mod in self.modules.values():
            self._collect_imports(mod)
            self._collect_defs(mod, mod.tree.body, prefix="", parent_fn=None, cls=None)
            for stmt in mod.tree.body:
                if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 \
                        and isinstance(stmt.targets[0], ast.Name) \
                        and isinstance(stmt.value, (ast.Name, ast.Attribute)):
                    mod.aliases[stmt.targets[0].id] = stmt.value
        for mod in self.modules.values():
            for info in mod.classes.values():
                for base in self.class_bases(info):
                    self.subclasses[base].append((info.module, info.qual))

    def _collect_imports(self, mod: PyModule):
        for node in ast.walk(mod.tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    target = self.find_module(alias.name, mod.rel)
                    local = alias.asname or alias.name.split(".")[0]
                    if alias.asname is None and "." in alias.name:
                        target = self.find_module(alias.name.split(".")[0], mod.rel) or target
                    mod.imports[local] = ("mod", target) if target else ("ext", alias.name)
            elif isinstance(node, ast.ImportFrom):
                if node.level:
                    base = self.relative_base(mod.rel, node.level)
                    parts = base + (node.module.split(".") if node.module else [])
                    src = self.module_from_parts(parts)
                    pkg_parts = parts
                else:
                    src = self.find_module(node.module or "", mod.rel)
                    pkg_parts = src.rsplit("/", 1)[0].split("/") if src and src.endswith("__init__.py") else None
                for alias in node.names:
                    if alias.name == "*":
                        continue
                    local = alias.asname or alias.name
                    sub = self.module_from_parts(pkg_parts + [alias.name]) if pkg_parts else None
                    if src and not sub:
                        mod.imports[local] = ("sym", src, alias.name)
                    elif sub:
                        mod.imports[local] = ("mod", sub) if not (src and self._defines(src, alias.name)) \
                            else ("sym", src, alias.name)
                    else:
                        mod.imports[local] = ("ext", f"{node.module}.{alias.name}")

    def _defines(self, rel, name):
        mod = self.modules[rel]
        return name in mod.funcs or name in mod.classes or name in mod.imports

    def _collect_defs(self, mod, body, prefix, parent_fn, cls):
        for stmt in body:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                qual = f"{prefix}{stmt.name}"
                nid = f"{mod.rel}::{qual}"
                self._add_py_node(mod, stmt, qual, nid, parent_fn, cls)
                if cls is not None and parent_fn is None:
                    cls.methods[stmt.name] = nid
                    if not stmt.name.startswith("__"):
                        self.method_names[stmt.name].append(nid)
                elif parent_fn is None and cls is None:
                    mod.funcs[stmt.name] = nid
                self._collect_defs(mod, stmt.body, f"{qual}.", nid, None)
            elif isinstance(stmt, ast.ClassDef):
                qual = f"{prefix}{stmt.name}"
                info = ClassInfo(mod.rel, qual, stmt)
                mod.classes[qual] = info
                self._collect_defs(mod, stmt.body, f"{qual}.", parent_fn, info)
            elif isinstance(stmt, (ast.If, ast.Try, ast.With, ast.AsyncWith, ast.For, ast.While)):
                for block in ("body", "orelse", "finalbody"):
                    self._collect_defs(mod, getattr(stmt, block, []) or [], prefix, parent_fn, cls)
                for handler in getattr(stmt, "handlers", []):
                    self._collect_defs(mod, handler.body, prefix, parent_fn, cls)

    def _add_py_node(self, mod, fn, qual, nid, parent_fn, cls):
        args = fn.args
        params = [a.arg for a in args.posonlyargs + args.args]
        if args.vararg:
            params.append("*" + args.vararg.arg)
        params += [a.arg for a in args.kwonlyargs]
        if args.kwarg:
            params.append("**" + args.kwarg.arg)
        returns = ast.unparse(fn.returns) if fn.returns else ""
        decorators = [ast.unparse(d) for d in fn.decorator_list]
        route = None
        entry_dec = any(re.search(r"\b(tool|command|fixture|on_event|task|resource|prompt)\b", d) for d in decorators)
        for dec in fn.decorator_list:
            if isinstance(dec, ast.Call) and ROUTE_DECORATOR.match(ast.unparse(dec.func)) and dec.args \
                    and isinstance(dec.args[0], ast.Constant) and isinstance(dec.args[0].value, str):
                route = (ast.unparse(dec.func).split(".")[-1].upper(), dec.args[0].value)
                self.routes.append((route[0], route[1], nid))
        doc = ast.get_docstring(fn) or ""
        kind = "nested" if parent_fn else ("method" if cls else "function")
        name = fn.name
        self.graph.nodes[nid] = {
            "id": nid, "name": name, "qual": qual, "file": mod.rel, "line": fn.lineno,
            "end": getattr(fn, "end_lineno", fn.lineno), "lang": "py", "kind": kind,
            "async": isinstance(fn, ast.AsyncFunctionDef),
            "sig": f"{'async ' if isinstance(fn, ast.AsyncFunctionDef) else ''}def {name}({', '.join(params)})"
                   + (f" -> {returns}" if returns else ""),
            "doc": doc.strip().split("\n\n")[0][:400], "decorators": decorators,
            "route": f"{route[0]} {route[1]}" if route else "", "parent": parent_fn or "",
            "cls": cls.qual if cls else "", "area": area_of(mod.rel),
            "test": is_test(mod.rel, qual), "entry": bool(route) or entry_dec or name == "main",
            "property": any(d.endswith(("property", "setter", "abstractmethod")) for d in decorators),
            "external": [],
        }

    # -- symbol resolution -----------------------------------------------------
    def resolve_symbol(self, rel, name, depth=0):
        """-> ('func', id) | ('class', ClassInfo) | ('mod', rel) | ('ext', label) | None"""
        if depth > 8 or rel not in self.modules:
            return None
        mod = self.modules[rel]
        if name in mod.funcs:
            return ("func", mod.funcs[name])
        if name in mod.classes:
            return ("class", mod.classes[name])
        if name in mod.imports:
            imp = mod.imports[name]
            if imp[0] == "mod":
                return ("mod", imp[1])
            if imp[0] == "sym":
                return self.resolve_symbol(imp[1], imp[2], depth + 1) or ("ext", f"{imp[2]}")
            return ("ext", imp[1])
        if name in mod.aliases:
            return self.resolve_expr_static(rel, mod.aliases[name], depth + 1)
        return None

    def resolve_expr_static(self, rel, expr, depth=0):
        if isinstance(expr, ast.Name):
            return self.resolve_symbol(rel, expr.id, depth)
        if isinstance(expr, ast.Attribute):
            base = self.resolve_expr_static(rel, expr.value, depth)
            if base and base[0] == "mod":
                return self.resolve_symbol(base[1], expr.attr, depth + 1)
            if base and base[0] == "class":
                mid = self.lookup_method((base[1].module, base[1].qual), expr.attr)
                return ("func", mid) if mid else None
        return None

    def class_bases(self, info: ClassInfo):
        if info.bases is None:
            info.bases = []
            for base in info.node.bases:
                res = self.resolve_expr_static(info.module, base)
                if not res and isinstance(base, ast.Name):
                    # class defined later in same module under a nested qual
                    cand = self.modules[info.module].classes.get(base.id)
                    res = ("class", cand) if cand else None
                if res and res[0] == "class":
                    info.bases.append((res[1].module, res[1].qual))
        return info.bases

    def class_info(self, key):
        mod = self.modules.get(key[0])
        return mod.classes.get(key[1]) if mod else None

    def lookup_method(self, key, name, skip_self=False, seen=None):
        seen = seen or set()
        if key in seen:
            return None
        seen.add(key)
        info = self.class_info(key)
        if not info:
            return None
        if not skip_self and name in info.methods:
            return info.methods[name]
        for base in self.class_bases(info):
            found = self.lookup_method(base, name, False, seen)
            if found:
                return found
        return None

    def overrides(self, key, name, seen=None):
        seen = seen or set()
        out = []
        for sub in self.subclasses.get(key, []):
            if sub in seen:
                continue
            seen.add(sub)
            info = self.class_info(sub)
            if info and name in info.methods:
                out.append(info.methods[name])
            out += self.overrides(sub, name, seen)
        return out

    def lookup_attr_type(self, key, attr, seen=None):
        seen = seen or set()
        if key in seen:
            return None
        seen.add(key)
        info = self.class_info(key)
        if not info:
            return None
        if attr in info.attr_types:
            return info.attr_types[attr]
        for base in self.class_bases(info):
            found = self.lookup_attr_type(base, attr, seen)
            if found:
                return found
        return None

    # -- pass 2: bodies --------------------------------------------------------
    def analyze(self):
        # attribute types first (self.x = Cls(...)) so method bodies can use them
        for mod in self.modules.values():
            for info in mod.classes.values():
                for meth in info.node.body:
                    if isinstance(meth, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        for node in ast.walk(meth):
                            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                                cls = self._class_of_value(mod.rel, node.value, {}) if node.value else None
                                if not cls and isinstance(node, ast.AnnAssign):
                                    cls = self._class_of_annotation(mod.rel, node.annotation)
                                for t in targets:
                                    if cls and isinstance(t, ast.Attribute) and isinstance(t.value, ast.Name) \
                                            and t.value.id == "self":
                                        info.attr_types[t.attr] = cls
                for stmt in info.node.body:          # dataclass-style  field: Type
                    if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
                        cls = self._class_of_annotation(mod.rel, stmt.annotation)
                        if cls:
                            info.attr_types.setdefault(stmt.target.id, cls)
        for mod in self.modules.values():
            self._walk_scope(mod, mod.tree.body, owner=None, cls_key=None, local_defs=[{}], var_types={})

    def _class_of_annotation(self, rel, ann):
        if isinstance(ann, ast.Constant) and isinstance(ann.value, str):
            try:
                ann = ast.parse(ann.value, mode="eval").body
            except SyntaxError:
                return None
        if isinstance(ann, ast.Subscript):        # Optional[X], list[X] -> X
            inner = ann.slice
            if isinstance(inner, ast.Tuple) and inner.elts:
                inner = inner.elts[0]
            return self._class_of_annotation(rel, inner)
        if isinstance(ann, ast.BinOp):           # X | None
            return self._class_of_annotation(rel, ann.left) or self._class_of_annotation(rel, ann.right)
        res = self.resolve_expr_static(rel, ann) if isinstance(ann, (ast.Name, ast.Attribute)) else None
        return (res[1].module, res[1].qual) if res and res[0] == "class" else None

    def _class_of_value(self, rel, value, var_types):
        if isinstance(value, ast.Call):
            res = self.resolve_expr_static(rel, value.func)
            if res and res[0] == "class":
                return (res[1].module, res[1].qual)
        if isinstance(value, ast.Name) and value.id in var_types:
            return var_types[value.id]
        return None

    def _walk_scope(self, mod, body, owner, cls_key, local_defs, var_types):
        """Visit statements of one scope. owner is the node id calls are attributed to."""
        module_owner = f"{mod.rel}::<module>"
        for stmt in body:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                qual_prefix = self.graph.nodes[owner]["qual"] + "." if owner and owner in self.graph.nodes \
                    else (cls_key[1] + "." if cls_key else "")
                nid = f"{mod.rel}::{qual_prefix}{stmt.name}"
                if nid not in self.graph.nodes:
                    continue
                for dec in stmt.decorator_list:         # decorators run in the enclosing scope
                    self._visit_expr(mod, dec, owner or module_owner, cls_key, local_defs, var_types)
                inner_defs = {s.name: f"{nid}.{s.name}" for s in stmt.body
                              if isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef))}
                types = dict(var_types) if owner else {}
                for arg in stmt.args.posonlyargs + stmt.args.args + stmt.args.kwonlyargs:
                    if arg.annotation is not None:
                        cls = self._class_of_annotation(mod.rel, arg.annotation)
                        if cls:
                            types[arg.arg] = cls
                self._walk_scope(mod, stmt.body, nid, cls_key if owner is None or cls_key else None,
                                 local_defs + [inner_defs], types)
            elif isinstance(stmt, ast.ClassDef):
                key = (mod.rel, (self.graph.nodes[owner]["qual"] + "." if owner in self.graph.nodes else "")
                       + stmt.name) if owner else (mod.rel, (cls_key[1] + "." if cls_key else "") + stmt.name)
                if key[1] not in mod.classes:
                    key = (mod.rel, stmt.name)
                for expr in stmt.bases + stmt.decorator_list:
                    self._visit_expr(mod, expr, owner or module_owner, cls_key, local_defs, var_types)
                self._walk_scope(mod, stmt.body, None, key, local_defs, var_types) if owner is None \
                    else self._walk_scope_class_in_fn(mod, stmt.body, key, local_defs, var_types)
            else:
                if cls_key and owner is None:
                    # class body statements (constants, field defaults) -- attribute to nothing
                    continue
                self._track_types(mod, stmt, var_types)
                self._visit_expr(mod, stmt, owner or module_owner, cls_key, local_defs, var_types)

    def _walk_scope_class_in_fn(self, mod, body, key, local_defs, var_types):
        for stmt in body:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self._walk_scope(mod, [stmt], None, key, local_defs, var_types)

    def _track_types(self, mod, stmt, var_types):
        for node in ast.walk(stmt):
            if isinstance(node, ast.Assign):
                cls = self._class_of_value(mod.rel, node.value, var_types)
                for t in node.targets:
                    if isinstance(t, ast.Name):
                        if cls:
                            var_types[t.id] = cls
                        else:
                            var_types.pop(t.id, None)
            elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                cls = self._class_of_annotation(mod.rel, node.annotation)
                if cls:
                    var_types[node.target.id] = cls
            elif isinstance(node, (ast.With, ast.AsyncWith)):
                for item in node.items:
                    if isinstance(item.optional_vars, ast.Name):
                        cls = self._class_of_value(mod.rel, item.context_expr, var_types)
                        if cls:
                            var_types[item.optional_vars.id] = cls

    def _visit_expr(self, mod, root, owner, cls_key, local_defs, var_types):
        called = set()
        stack = [root]
        while stack:
            node = stack.pop()
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node is not root:
                continue
            if isinstance(node, ast.Call):
                called.add(id(node.func))
                self._record_call(mod, node, owner, cls_key, local_defs, var_types)
            elif isinstance(node, (ast.Name, ast.Attribute)) and id(node) not in called \
                    and isinstance(getattr(node, "ctx", None), ast.Load):
                target = self._resolve_callable(mod, node, cls_key, local_defs, var_types, quiet=True)
                if target and target[0] == "call":
                    self._ensure_owner(mod, owner)
                    self.graph.add_edge(owner, target[1][0], "ref", node.lineno)
                if isinstance(node, ast.Attribute):
                    # don't double-count the inner Name of a resolved attribute reference
                    if target:
                        continue
            stack.extend(ast.iter_child_nodes(node))

    def _ensure_owner(self, mod, owner):
        if owner.endswith("::<module>") and owner not in self.graph.nodes:
            self.graph.nodes[owner] = {
                "id": owner, "name": "<module>", "qual": "<module>", "file": mod.rel, "line": 1,
                "end": len(mod.source.splitlines()), "lang": "py", "kind": "module",
                "async": False, "sig": f"module-level code in {mod.rel}", "doc": ast.get_docstring(mod.tree) or "",
                "decorators": [], "route": "", "parent": "", "cls": "", "area": area_of(mod.rel),
                "test": is_test(mod.rel, ""), "entry": True, "external": [],
            }

    def _record_call(self, mod, call, owner, cls_key, local_defs, var_types):
        target = self._resolve_callable(mod, call.func, cls_key, local_defs, var_types)
        self._ensure_owner(mod, owner)
        if target is None:
            label = ast.unparse(call.func)
            if len(label) > 60 or "\n" in label:
                label = label.replace("\n", " ")[:57] + "..."
            ext = self.graph.nodes[owner]["external"]
            if label not in ext:
                ext.append(label)
            return
        kind, ids = target
        for i, nid in enumerate(ids):
            edge_kind = kind if i == 0 or kind != "call" else "dispatch"
            self.graph.add_edge(owner, nid, edge_kind, call.lineno)

    def _resolve_callable(self, mod, func, cls_key, local_defs, var_types, quiet=False):
        """-> ('call'|'inferred', [ids]) or None"""
        if isinstance(func, ast.Name):
            for scope in reversed(local_defs):
                if func.id in scope and scope[func.id] in self.graph.nodes:
                    return ("call", [scope[func.id]])
            if func.id in var_types and not quiet:
                return None
            res = self.resolve_symbol(mod.rel, func.id)
            return self._from_symbol(res, quiet)
        if not isinstance(func, ast.Attribute):
            return None
        attr, value = func.attr, func.value
        recv = None   # class key of the receiver
        virtual = False
        if isinstance(value, ast.Name) and value.id in ("self", "cls") and cls_key:
            recv, virtual = cls_key, True
        elif isinstance(value, ast.Call) and isinstance(value.func, ast.Name) and value.func.id == "super" and cls_key:
            mid = self.lookup_method(cls_key, attr, skip_self=True)
            return ("call", [mid]) if mid else None
        elif isinstance(value, ast.Attribute) and isinstance(value.value, ast.Name) \
                and value.value.id == "self" and cls_key:
            recv = self.lookup_attr_type(cls_key, value.attr)
        elif isinstance(value, ast.Name) and value.id in var_types:
            recv = var_types[value.id]
        elif isinstance(value, ast.Call):
            recv = self._class_of_value(mod.rel, value, var_types)
        if recv is None and isinstance(value, (ast.Name, ast.Attribute)):
            res = self.resolve_expr_static(mod.rel, value)
            if res and res[0] == "mod":
                return self._from_symbol(self.resolve_symbol(res[1], attr), quiet)
            if res and res[0] == "class":
                recv = (res[1].module, res[1].qual)
            elif res and res[0] == "ext":
                return None
        if recv is not None:
            mid = self.lookup_method(recv, attr)
            ids = [mid] if mid else []
            if virtual or not mid:
                ids += [o for o in self.overrides(recv, attr) if o not in ids]
            if ids:
                return ("call", ids) if mid else ("inferred", ids)
            return None
        if quiet or attr.startswith("__") or attr in GENERIC_METHODS:
            return None
        cands = self.method_names.get(attr, [])
        if 1 <= len(cands) <= 2 and not (isinstance(value, ast.Name) and value.id in mod.imports
                                           and mod.imports[value.id][0] == "ext"):
            return ("inferred", list(cands))
        return None

    def _from_symbol(self, res, quiet):
        if not res:
            return None
        if res[0] == "func":
            return ("call", [res[1]])
        if res[0] == "class" and not quiet:
            init = self.lookup_method((res[1].module, res[1].qual), "__init__") \
                or self.lookup_method((res[1].module, res[1].qual), "__post_init__")
            return ("call", [init]) if init else None
        return None


# ----------------------------------------------------------------------------- JavaScript

def mask_js(src: str) -> str:
    """Blank out strings, template literals and comments (keeping length & newlines)."""
    out = list(src)
    i, n = 0, len(src)
    regex_ok = True
    while i < n:
        c = src[i]
        if c == "/" and i + 1 < n and src[i + 1] == "/":
            j = src.find("\n", i)
            j = n if j == -1 else j
            out[i:j] = " " * (j - i)
            i = j
            continue
        if c == "/" and i + 1 < n and src[i + 1] == "*":
            j = src.find("*/", i + 2)
            j = n if j == -1 else j + 2
            out[i:j] = [ch if ch == "\n" else " " for ch in src[i:j]]
            i = j
            continue
        if c in "'\"`":
            j = i + 1
            depth = 0
            while j < n:
                if src[j] == "\\":
                    j += 2
                    continue
                if c == "`" and src[j] == "$" and j + 1 < n and src[j + 1] == "{":
                    depth += 1
                elif c == "`" and depth and src[j] == "}":
                    depth -= 1
                elif src[j] == c and depth == 0:
                    break
                elif src[j] == "\n" and c != "`":
                    break
                j += 1
            for k in range(i + 1, min(j, n)):
                if out[k] != "\n":
                    out[k] = " "
            i = j + 1
            regex_ok = False
            continue
        if not c.isspace():
            regex_ok = c in "(,=:[!&|?{};"
        i += 1
    return "".join(out)


def match_bracket(masked: str, start: int) -> int:
    pairs = {"(": ")", "{": "}", "[": "]"}
    opener = masked[start]
    closer = pairs[opener]
    depth = 0
    for k in range(start, len(masked)):
        ch = masked[k]
        if ch == opener:
            depth += 1
        elif ch == closer:
            depth -= 1
            if depth == 0:
                return k
    return len(masked) - 1


def expr_end(masked: str, start: int) -> int:
    depth = 0
    for k in range(start, len(masked)):
        ch = masked[k]
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            if depth == 0:
                return k
            depth -= 1
        elif ch in ";," and depth == 0:
            return k
    return len(masked)


JS_DECL = [
    re.compile(r"(?:export\s+(?:default\s+)?)?(?:async\s+)?function\s*\*?\s*([A-Za-z_$][\w$]*)\s*\("),
    re.compile(r"(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?"
               r"(?:\((?:[^()]|\([^()]*\))*\)|[A-Za-z_$][\w$]*)\s*=>"),
    re.compile(r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:React\.)?(use(?:Callback|Memo|Effect))\s*\("),
    re.compile(r"\b(use(?:Effect|LayoutEffect))\s*\("),
]


def analyze_js(root: Path, files: list[Path], graph: Graph, routes):
    file_decls = {}
    for path in files:
        rel = path.relative_to(root).as_posix()
        src = path.read_text(encoding="utf-8", errors="replace")
        masked = mask_js(src)
        line_at = _line_index(src)
        decls = []
        effect_count = defaultdict(int)
        for pi, pattern in enumerate(JS_DECL):
            for m in pattern.finditer(masked):
                name = m.group(1)
                if pi == 3:
                    effect_count[name] += 1
                    name = f"{name}#{effect_count[name]}"
                    open_at = m.end() - 1
                    end = match_bracket(masked, open_at)
                elif pi == 2:
                    open_at = m.end() - 1
                    end = match_bracket(masked, open_at)
                elif pi == 0:
                    params_end = match_bracket(masked, m.end() - 1)
                    brace = masked.find("{", params_end)
                    end = match_bracket(masked, brace) if brace != -1 else params_end
                else:
                    k = m.end()
                    while k < len(masked) and masked[k].isspace():
                        k += 1
                    end = match_bracket(masked, k) if k < len(masked) and masked[k] == "{" else expr_end(masked, k)
                params = ""
                pm = re.search(r"\(([^)]*)\)", src[m.start(): m.end() + 200])
                if pm and pi in (0, 1):
                    params = re.sub(r"\s+", " ", pm.group(1)).strip()
                decls.append({"name": name, "start": m.start(), "end": end, "params": params,
                              "kind_hint": pi, "exported": src[m.start():m.start() + 6] == "export"})
        # drop duplicate matches of the same span (e.g. useEffect inside useCallback pattern)
        seen, unique = set(), []
        for d in sorted(decls, key=lambda d: (d["start"], -d["end"])):
            key = (d["start"], d["name"])
            if key in seen or any(u["name"] == d["name"] and u["start"] <= d["start"] <= u["end"]
                                  and d["kind_hint"] == 3 and u["kind_hint"] == 2 for u in unique):
                continue
            seen.add(key)
            unique.append(d)
        # nesting
        for d in unique:
            parents = [p for p in unique if p is not d and p["start"] < d["start"] and d["end"] <= p["end"]]
            d["parent"] = max(parents, key=lambda p: p["start"]) if parents else None
        for d in unique:
            chain, p = [d["name"]], d["parent"]
            while p:
                chain.append(p["name"])
                p = p["parent"]
            d["qual"] = ".".join(reversed(chain))
            d["id"] = f"{rel}::{d['qual']}"
            first_line = src[d["start"]: src.find("\n", d["start"])].strip()
            graph.nodes[d["id"]] = {
                "id": d["id"], "name": d["name"], "qual": d["qual"], "file": rel,
                "line": line_at(d["start"]), "end": line_at(d["end"]), "lang": "js",
                "kind": "hook" if d["kind_hint"] >= 2 else ("component" if d["name"][:1].isupper() else
                                                            ("nested" if d["parent"] else "function")),
                "async": "async" in first_line.split("(")[0], "sig": first_line[:160],
                "doc": "", "decorators": [], "route": "", "parent": d["parent"]["id"] if d["parent"] else "",
                "cls": "", "area": area_of(rel), "test": is_test(rel, d["name"]),
                "entry": d["exported"] or rel.endswith("main.jsx"), "external": [],
            }
        file_decls[rel] = (src, masked, unique, line_at)

    # imports between JS files
    imports = defaultdict(dict)
    for rel, (src, masked, decls, _) in file_decls.items():
        for m in re.finditer(r"import\s+([\w$]+)?\s*,?\s*(?:\{([^}]*)\})?\s*from\s*['\"](\.{1,2}/[^'\"]+)['\"]", src):
            target = _resolve_js_path(rel, m.group(3), file_decls)
            if not target:
                continue
            tdecls = file_decls[target][2]
            if m.group(1):
                exp = [d for d in tdecls if src and file_decls[target][0][d["start"]:d["start"] + 14] == "export default"]
                if exp:
                    imports[rel][m.group(1)] = exp[0]["id"]
            for spec in (m.group(2) or "").split(","):
                parts = spec.strip().split(" as ")
                if parts[0]:
                    top = [d for d in tdecls if d["name"] == parts[0].strip() and not d["parent"]]
                    if top:
                        imports[rel][parts[-1].strip()] = top[0]["id"]

    route_res = [(meth, re.compile("^" + re.sub(r"\\\{[^}]+\\\}", "[^/]+", re.escape(path)) + "$"), nid)
                 for meth, path, nid in routes]
    module_nodes = {}
    for rel, (src, masked, decls, line_at) in file_decls.items():
        by_name = defaultdict(list)
        for d in decls:
            by_name[d["name"]].append(d)

        def owner_at(pos):
            inside = [d for d in decls if d["start"] < pos <= d["end"]]
            if inside:
                return max(inside, key=lambda d: d["start"])["id"]
            mid = f"{rel}::<module>"
            if mid not in graph.nodes:
                graph.nodes[mid] = {
                    "id": mid, "name": "<module>", "qual": "<module>", "file": rel, "line": 1,
                    "end": line_at(len(src)), "lang": "js", "kind": "module", "async": False,
                    "sig": f"module-level code in {rel}", "doc": "", "decorators": [], "route": "",
                    "parent": "", "cls": "", "area": area_of(rel), "test": False, "entry": True, "external": []}
            module_nodes[rel] = mid
            return mid

        def target_for(name, pos):
            cands = by_name.get(name)
            if cands:
                visible = [d for d in cands if d["parent"] is None or d["parent"]["start"] < pos <= d["parent"]["end"]]
                pick = max(visible or cands, key=lambda d: d["start"])
                return pick["id"]
            return imports[rel].get(name)

        decl_starts = {d["start"] for d in decls}
        for m in re.finditer(r"(?<![\w$.])([A-Za-z_$][\w$]*)\b", masked):
            name = m.group(1)
            if name not in by_name and name not in imports[rel]:
                continue
            pos = m.start()
            line_start = masked.rfind("\n", 0, pos) + 1
            if any(line_start <= s <= pos for s in decl_starts) and \
                    re.search(r"(function\s*\*?\s*|(?:const|let|var)\s+)$", masked[line_start:pos]):
                continue
            target = target_for(name, pos)
            owner = owner_at(pos)
            if not target or target == owner:
                continue
            rest = masked[m.end(): m.end() + 3].lstrip()
            prev = masked[max(0, pos - 1)]
            if rest.startswith("("):
                kind = "call"
            elif prev == "<":
                kind = "call"           # <Component />
            else:
                kind = "ref"
            graph.add_edge(owner, target, kind, line_at(pos))
        # external calls (fetch, setX, etc.) per owner -- keep it short
        for m in re.finditer(r"(?<![\w$])((?:[A-Za-z_$][\w$]*\.)*[A-Za-z_$][\w$]*)\s*\(", masked):
            name = m.group(1)
            if name.split(".")[0] in by_name or name in imports[rel] or name in (
                    "if", "for", "while", "switch", "catch", "function", "return", "typeof"):
                continue
            owner = owner_at(m.start())
            ext = graph.nodes[owner]["external"]
            if name not in ext and len(ext) < 40:
                ext.append(name)
        # UI -> API
        for m in re.finditer(r"([`'\"])(/api/[^`'\"]*)\1", src):
            url = re.sub(r"\$\{[^}]*\}", "X", m.group(2)).split("?")[0]
            for meth, rx, nid in route_res:
                if rx.match(url):
                    graph.add_edge(owner_at(m.start()), nid, "http", line_at(m.start()))
    return module_nodes


def _line_index(src):
    starts = [0] + [i + 1 for i, ch in enumerate(src) if ch == "\n"]

    def line_at(pos):
        lo, hi = 0, len(starts) - 1
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if starts[mid] <= pos:
                lo = mid
            else:
                hi = mid - 1
        return lo + 1
    return line_at


def _resolve_js_path(rel, spec, file_decls):
    base = Path(rel).parent
    raw = os.path.normpath((base / spec).as_posix()).replace("\\", "/")
    for cand in (raw, *(raw + e for e in (".jsx", ".js", ".tsx", ".ts")), *(f"{raw}/index{e}" for e in (".jsx", ".js"))):
        if cand in file_decls:
            return cand
    return None


# ----------------------------------------------------------------------------- output

def build(root: Path, exclude=()):
    graph = Graph()
    py_files, js_files = discover(root, exclude)
    py = PyAnalyzer(root, py_files, graph)
    py.collect()
    py.analyze()
    analyze_js(root, js_files, graph, py.routes)

    edges = [{"s": s, "t": t, "k": k, "lines": sorted(lines)} for (s, t, k), lines in graph.edges.items()
             if s in graph.nodes and t in graph.nodes]
    # drop 'ref' / 'inferred' edges that duplicate a direct call
    direct = {(e["s"], e["t"]) for e in edges if e["k"] in ("call", "http")}
    edges = [e for e in edges if e["k"] in ("call", "http") or (e["s"], e["t"]) not in direct]
    files = {}
    for path in py_files + js_files:
        rel = path.relative_to(root).as_posix()
        if any(n["file"] == rel for n in graph.nodes.values()):
            src = path.read_text(encoding="utf-8", errors="replace")
            files[rel] = {"area": area_of(rel), "lines": src.count("\n") + 1, "src": src}
    return {
        "root": str(root.resolve()).replace("\\", "/"),
        "generated": datetime.now().strftime("%Y-%m-%d %H:%M"),
        "nodes": list(graph.nodes.values()), "edges": edges, "files": files,
        "parseErrors": py.parse_errors,
    }


def main():
    here = Path(__file__).resolve().parent
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--root", default=str(here.parent.parent), help="repository root to scan")
    ap.add_argument("--out", default=str(here / "callgraph.html"), help="HTML file to write")
    ap.add_argument("--exclude", action="append", default=None,
                    help="directory (relative to root) to skip; repeatable. Default: tools/callgraph")
    ap.add_argument("--json", help="also write the raw graph JSON here")
    args = ap.parse_args()
    data = build(Path(args.root), args.exclude if args.exclude is not None else ["tools/callgraph"])
    payload = json.dumps(data, separators=(",", ":")).replace("</", "<\\/")
    template = (here / "viewer.html").read_text(encoding="utf-8")
    Path(args.out).write_text(template.replace("/*__GRAPH_DATA__*/null", payload), encoding="utf-8")
    if args.json:
        Path(args.json).write_text(json.dumps(data, indent=1), encoding="utf-8")
    kinds = defaultdict(int)
    for e in data["edges"]:
        kinds[e["k"]] += 1
    print(f"{len(data['nodes'])} functions across {len(data['files'])} files, "
          f"{len(data['edges'])} edges ({', '.join(f'{k}={v}' for k, v in sorted(kinds.items()))})")
    for err in data["parseErrors"]:
        print(f"  skipped (syntax error): {err}")
    print(f"wrote {args.out}")


if __name__ == "__main__":
    main()
