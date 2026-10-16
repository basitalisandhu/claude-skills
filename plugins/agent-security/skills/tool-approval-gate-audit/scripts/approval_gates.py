#!/usr/bin/env python3
"""Audit Python agent code for consequential tools that a model can call without a deterministic human approval gate.

The script parses Python source with the standard library `ast` module (it never imports or runs it), finds every tool
definition it recognises, decides from the body and the tool name whether the tool has a consequential side effect, and
checks whether a gate that runs in code, outside the model, stands in front of it.

Tool definitions recognised:
  openai-agents  @function_tool / @function_tool(...), FunctionTool(...); gate: needs_approval=
  langchain      @tool / @tool("name"), StructuredTool.from_function(...), Tool(...), BaseTool subclasses with _run;
                 gate: interrupt() in the body, the tool (or the ToolNode holding it) named in interrupt_before= or
                 interrupt_after=, or a HumanInTheLoop / human_in_the_loop wrapper that names or wraps the tool
  crewai         @tool from crewai, BaseTool subclasses with _run; gate: a Task(..., human_input=True) that lists the
                 tool (reported for review), or an approval call in the body
  mcp            @<server>.tool(...) such as @mcp.tool() or @server.tool(); reads annotations= (ToolAnnotations(...) or
                 a dict) for readOnlyHint and destructiveHint
  any            an approval-shaped call in the body or a same-module helper: a name with approve, approval, confirm,
                 human or ask_user (not one that also has a side-effect verb or ends in message or email), or input()

Findings (id, severity):
  NO-GATE                  high    consequential tool with no gate (needs_approval=False counts as none)
  GATE-NOT-BOOL            high    needs_approval is a literal that is not True or False (a string, number, None, ...)
  GATE-RESULT-IGNORED      high    input() or interrupt() is called but its answer is thrown away, so a refusal cannot
                                   stop the tool; medium for another approval-named call whose result is discarded
                                   (fine only if it raises on refusal; names starting require, ensure or assert are
                                   taken to raise)
  READONLY-HINT-BUT-WRITES medium  MCP tool annotated readOnlyHint=True whose body has side effects
  POLICY-MISMATCH          medium  the gate differs from --policy, or the policy names a tool that was not found
  DESTRUCTIVE-NO-HINT      low     MCP delete-type tool without destructiveHint=True (medium when it says False)
  GATE-CONDITIONAL         info    the gate is a callable, a variable or a task-level review: read it
  GATE-ON-READ-ONLY        info    an unconditional gate on a read-only tool (approval fatigue)

A --policy file is a JSON object {"tool_name": "always" | "never" | "conditional"}. A tool the policy marks "never"
is not reported as NO-GATE, and one it marks "always" is not reported as GATE-ON-READ-ONLY: the decision is recorded.

Usage:
  approval_gates.py [ROOT] [--format markdown|json] [--policy FILE] [--fail-on high|medium|low] [--strict] [--out FILE]

Exit codes: 0 no finding at or above --fail-on (default high), 1 findings at or above --fail-on, 2 bad input or usage
(missing root, unreadable or malformed policy, or with --strict a Python file that does not parse; without --strict
such files are listed as skipped). Standard library only. Read-only. No network.
"""
from __future__ import annotations

import argparse
import ast
import json
import re
import sys
from pathlib import Path

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "dist", "build", "__pycache__", ".tox", "site-packages", ".mypy_cache"}
MAX_FILES = 5000  # stop walking after this many Python files; the summary says so
MAX_FILE_BYTES = 1_000_000  # skip larger files; they are listed as skipped
SEVERITIES = ["high", "medium", "low", "info"]
RANK = {s: i for i, s in enumerate(SEVERITIES)}

# Tool-name verbs that make a tool consequential even when the body shows no recognised side effect.
CONSEQUENTIAL_VERBS = frozenset({"send", "delete", "remove", "drop", "write", "create", "update", "deploy", "execute",
                                 "run", "transfer", "pay", "publish", "post", "move"})
DELETE_VERBS = frozenset({"delete", "remove", "drop"})
SUBPROCESS_FUNCS = {"run", "call", "check_call", "check_output", "Popen", "getoutput", "getstatusoutput"}
HTTP_WRITE_METHODS = {"post", "put", "patch", "delete"}
CLOUD_WRITE_PREFIXES = ("delete_", "put_", "create_", "update_", "terminate_", "attach_")
MAIL_FUNCS = {"sendmail", "send_message", "send_mail"}
SQL_WRITE = re.compile(r"(?i)^\s*(INSERT|UPDATE|DELETE|DROP)\b")
POLICY_VALUES = {"always", "never", "conditional"}

FIXES = {
    "NO-GATE": "Put a deterministic approval in front of the tool (needs_approval=True, interrupt() before the side "
               "effect, or an approval call whose refusal stops the tool), or record a reviewed 'never' in the policy.",
    "GATE-NOT-BOOL": "Pass True, False or a function that returns a bool; never a string, number or None.",
    "GATE-RESULT-IGNORED": "Use the answer: stop the tool (return or raise) unless the approval call says yes.",
    "READONLY-HINT-BUT-WRITES": "Set readOnlyHint=False, or move the write into a separate tool.",
    "POLICY-MISMATCH": "Change the gate or the policy so they agree, and say which one was wrong in the review.",
    "DESTRUCTIVE-NO-HINT": "Set destructiveHint=True in the tool annotations, and still gate it: hints are advisory.",
    "GATE-CONDITIONAL": "Read the condition: it must be deterministic code, fail closed on errors, and cover every "
                        "consequential argument.",
    "GATE-ON-READ-ONLY": "Drop the approval on read-only tools so reviewers keep paying attention to the ones that act.",
}


class UsageError(Exception):
    pass


def dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return f"{dotted(node.value)}.{node.attr}"
    if isinstance(node, ast.Call):
        return f"{dotted(node.func)}()"
    return "<expr>"


def last_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return ""


def words(name: str) -> list[str]:
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name)
    return [w for w in re.split(r"[^A-Za-z0-9]+", spaced.lower()) if w]


def short(node: ast.AST, limit: int = 80) -> str:
    try:
        text = ast.unparse(node)
    except Exception:  # pragma: no cover - unparse handles every node ast.parse produces
        text = "<expr>"
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 3] + "..."


def str_const(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def kwarg(call: ast.Call, name: str) -> ast.AST | None:
    for kw in call.keywords:
        if kw.arg == name:
            return kw.value
    return None


def side_effect(call: ast.Call) -> str | None:
    """The side-effect kind of one call, or None when it is not a recognised write."""
    fn = call.func
    full = dotted(fn)
    last = last_name(fn)
    root = full.split(".")[0]
    if root == "subprocess" and last in SUBPROCESS_FUNCS:
        return "process"
    if full in {"os.system", "os.popen"}:
        return "process"
    if full in {"os.remove", "os.unlink", "os.rmdir", "shutil.rmtree"}:
        return "file-delete"
    if full in {"shutil.move", "os.rename", "os.replace"}:
        return "file-move"
    if full in {"open", "io.open"}:
        mode = call.args[1] if len(call.args) > 1 else kwarg(call, "mode")
        value = str_const(mode)
        if value is not None and set(value) & set("wax+"):
            return "file-write"
        return None
    if isinstance(fn, ast.Attribute):
        if last in {"write_text", "write_bytes"}:
            return "file-write"
        if last in {"unlink", "rmdir"}:
            return "file-delete"
        if last in HTTP_WRITE_METHODS:
            return "network-write"
        if last.startswith(CLOUD_WRITE_PREFIXES):
            return "cloud-write"
        if last in {"execute", "executemany", "executescript"} and call.args:
            first = call.args[0]
            text = str_const(first)
            if text is None and isinstance(first, ast.JoinedStr):
                text = "".join(v.value for v in first.values if isinstance(v, ast.Constant) and isinstance(v.value, str))
            if text and SQL_WRITE.search(text):
                return "sql-write"
    if root == "smtplib" or last in MAIL_FUNCS:
        return "mail"
    return None


def is_delete_effect(effect: dict) -> bool:
    if effect["kind"] == "file-delete":
        return True
    ev = effect["evidence"]
    return bool(re.search(r"\.delete\(|\.delete_|(?i:\b(DELETE|DROP)\b)", ev))


def gate_call_kind(call: ast.Call) -> str | None:
    """'interrupt', 'input' or 'approval-call' when the call looks like a human approval, else None."""
    fn = call.func
    last = last_name(fn)
    if not last:
        return None
    if last == "interrupt":
        return "interrupt"
    if isinstance(fn, ast.Name) and last == "input":
        return "input"
    w = words(last)
    named = any(x.startswith(("approv", "confirm")) or x == "human" for x in w) or "ask_user" in last.lower()
    if not named:
        return None
    if any(x in CONSEQUENTIAL_VERBS for x in w) or w[-1] in {"message", "messages", "email", "mail"}:
        return None
    return "approval-call"


def is_hitl_wrapper(node: ast.AST) -> bool:
    return "humanintheloop" in last_name(node).lower().replace("_", "")


class Module:
    """One parsed file: imports, module-level functions and assignments, used to resolve names."""

    def __init__(self, tree: ast.Module, rel: str):
        self.tree = tree
        self.rel = rel
        self.origin: dict[str, str] = {}
        self.funcs: dict[str, ast.AST] = {}
        self.assigns: dict[str, ast.AST] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                for alias in node.names:
                    self.origin[alias.asname or alias.name] = node.module
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    self.origin[alias.asname or alias.name.split(".")[0]] = alias.name
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.funcs[node.name] = node
            elif isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                self.assigns[node.targets[0].id] = node.value
            elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.value is not None:
                self.assigns[node.target.id] = node.value

    def framework_of(self, local: str, default: str) -> str:
        mod = self.origin.get(local, "")
        if mod.startswith("crewai"):
            return "crewai"
        if mod.startswith(("langchain", "langgraph")):
            return "langchain"
        if mod == "agents" or mod.startswith("agents."):
            return "openai-agents"
        if any(m.startswith("crewai") for m in self.origin.values()) and default == "langchain":
            return "crewai"
        return default

    def resolve(self, node: ast.AST | None) -> ast.AST | None:
        seen = 0
        while isinstance(node, ast.Name) and node.id in self.assigns and seen < 5:
            node = self.assigns[node.id]
            seen += 1
        return node


def scan_body(mod: Module, nodes: list[ast.AST]) -> tuple[list[dict], list[dict]]:
    """Side effects and approval-shaped calls in the given nodes, following calls to same-module functions."""
    effects: list[dict] = []
    gates: list[dict] = []
    visited: set[str] = set()

    def visit(items: list[ast.AST], via: str | None) -> None:
        # walk bodies only, so decorators such as @function_tool(...) are not read as calls made by the tool
        items = [s for i in items for s in (i.body if isinstance(i, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) else [i])]
        ignored: set[int] = set()
        for item in items:
            for node in ast.walk(item):
                if isinstance(node, ast.Expr):
                    value = node.value.value if isinstance(node.value, ast.Await) else node.value
                    if isinstance(value, ast.Call):
                        ignored.add(id(value))
        for item in items:
            for node in ast.walk(item):
                if not isinstance(node, ast.Call):
                    continue
                suffix = f" via {via}()" if via else ""
                kind = side_effect(node)
                if kind:
                    effects.append({"kind": kind, "evidence": short(node) + suffix, "file": mod.rel, "line": node.lineno})
                gkind = gate_call_kind(node)
                if gkind:
                    gates.append({"kind": gkind, "evidence": short(node) + suffix, "file": mod.rel, "line": node.lineno,
                                  "conditional": False, "result_ignored": id(node) in ignored})
                if isinstance(node.func, ast.Name) and node.func.id in mod.funcs and node.func.id not in visited:
                    visited.add(node.func.id)
                    visit([mod.funcs[node.func.id]], node.func.id)

    visit(nodes, None)
    uniq: dict[tuple, dict] = {}
    for e in effects:
        uniq.setdefault((e["kind"], e["file"], e["line"], e["evidence"]), e)
    return sorted(uniq.values(), key=lambda e: (e["file"], e["line"], e["kind"])), gates


def needs_approval_gate(mod: Module, value: ast.AST, line: int) -> dict:
    resolved = mod.resolve(value) if isinstance(value, ast.Name) else value
    evidence = f"needs_approval={short(value)}"
    base = {"evidence": evidence, "file": mod.rel, "line": line, "result_ignored": False}
    if isinstance(resolved, ast.Constant):
        if resolved.value is True:
            return {**base, "kind": "needs_approval", "conditional": False}
        if resolved.value is False:
            return {**base, "kind": "explicit-false", "conditional": False}
        return {**base, "kind": "not-bool", "conditional": False}
    if isinstance(resolved, (ast.Lambda, ast.Name, ast.Attribute, ast.Call, ast.BoolOp, ast.Compare, ast.UnaryOp, ast.IfExp)):
        return {**base, "kind": "needs_approval", "conditional": True}
    return {**base, "kind": "not-bool", "conditional": False}


def annotations_of(value: ast.AST | None) -> dict:
    out: dict = {}
    if isinstance(value, ast.Call):
        for kw in value.keywords:
            if kw.arg and isinstance(kw.value, ast.Constant):
                out[kw.arg] = kw.value.value
    elif isinstance(value, ast.Dict):
        for k, v in zip(value.keys, value.values):
            key = str_const(k)
            if key and isinstance(v, ast.Constant):
                out[key] = v.value
    return {k: v for k, v in out.items() if k in {"readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint"}}


def new_tool(mod: Module, name: str, symbol: str | None, framework: str, line: int, body: list[ast.AST]) -> dict:
    effects, gates = scan_body(mod, body)
    return {"name": name, "symbol": symbol, "framework": framework, "file": mod.rel, "line": line,
            "side_effects": effects, "gates": gates}


def find_tools(mod: Module) -> list[dict]:
    tools: list[dict] = []
    assigned: dict[int, str] = {}
    for node in ast.walk(mod.tree):
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            assigned[id(node.value)] = node.targets[0].id

    for node in ast.walk(mod.tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            tool = None
            wrapper_gates: list[dict] = []
            for dec in node.decorator_list:
                target = dec.func if isinstance(dec, ast.Call) else dec
                last = last_name(target)
                if is_hitl_wrapper(target):
                    wrapper_gates.append({"kind": "hitl-wrapper", "evidence": "@" + short(dec), "file": mod.rel,
                                          "line": dec.lineno, "conditional": False, "result_ignored": False})
                    continue
                call = dec if isinstance(dec, ast.Call) else None
                if last == "function_tool":
                    name = str_const(kwarg(call, "name_override")) if call else None
                    tool = new_tool(mod, name or node.name, node.name, "openai-agents", node.lineno, [node])
                    value = kwarg(call, "needs_approval") if call else None
                    if value is not None:
                        tool["gates"].insert(0, needs_approval_gate(mod, value, dec.lineno))
                elif last == "tool" and isinstance(target, ast.Attribute):
                    name = (str_const(kwarg(call, "name")) or (str_const(call.args[0]) if call.args else None)) if call else None
                    tool = new_tool(mod, name or node.name, node.name, "mcp", node.lineno, [node])
                    tool["annotations"] = annotations_of(mod.resolve(kwarg(call, "annotations")) if call else None)
                elif last == "tool" and isinstance(target, ast.Name):
                    name = str_const(call.args[0]) if call and call.args else None
                    tool = new_tool(mod, name or node.name, node.name, mod.framework_of("tool", "langchain"), node.lineno, [node])
            if tool:
                tool["gates"] = wrapper_gates + tool["gates"]
                tools.append(tool)
        elif isinstance(node, ast.ClassDef):
            base = next((b for b in node.bases if last_name(b) == "BaseTool"), None)
            if base is None:
                continue
            methods = {m.name for m in node.body if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef))}
            if not methods & {"_run", "_arun"}:
                continue
            name = None
            for stmt in node.body:
                if isinstance(stmt, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "name" for t in stmt.targets):
                    name = str_const(stmt.value)
                elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name) and stmt.target.id == "name":
                    name = str_const(stmt.value)
            root = dotted(base).split(".")[0]
            tools.append(new_tool(mod, name or node.name, node.name, mod.framework_of(root, "langchain"), node.lineno, [node]))
        elif isinstance(node, ast.Call):
            full = dotted(node.func)
            last = last_name(node.func)
            symbol = assigned.get(id(node))
            if last == "FunctionTool":
                func = mod.resolve(kwarg(node, "on_invoke_tool"))
                body = [mod.funcs[func.id]] if isinstance(func, ast.Name) and func.id in mod.funcs else []
                name = str_const(kwarg(node, "name")) or symbol or "<unnamed>"
                tool = new_tool(mod, name, symbol, "openai-agents", node.lineno, body)
                value = kwarg(node, "needs_approval")
                if value is not None:
                    tool["gates"].insert(0, needs_approval_gate(mod, value, node.lineno))
                tools.append(tool)
            elif full.endswith("Tool.from_function") or last == "Tool":
                if full.endswith("from_function"):
                    func = kwarg(node, "func") or kwarg(node, "coroutine") or (node.args[0] if node.args else None)
                    name = str_const(kwarg(node, "name"))
                else:
                    func = kwarg(node, "func") or (node.args[1] if len(node.args) > 1 else None)
                    name = str_const(kwarg(node, "name")) or (str_const(node.args[0]) if node.args else None)
                func = mod.resolve(func) if isinstance(func, ast.Name) and func.id not in mod.funcs else func
                body = [mod.funcs[func.id]] if isinstance(func, ast.Name) and func.id in mod.funcs else []
                if name is None and isinstance(func, ast.Name):
                    name = func.id
                tools.append(new_tool(mod, name or symbol or "<unnamed>", symbol, "langchain", node.lineno, body))
    return tools


def symbols_in(mod: Module, node: ast.AST | None) -> set[str]:
    """Tool references in a list: names, and class names of instances such as MyTool()."""
    node = mod.resolve(node)
    out: set[str] = set()
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        for elt in node.elts:
            if isinstance(elt, ast.Name):
                out.add(elt.id)
            elif isinstance(elt, ast.Call) and last_name(elt.func):
                out.add(last_name(elt.func))
    return out


def project_gates(mod: Module) -> list[dict]:
    """Gates declared away from the tool: interrupt lists, ToolNodes, wrappers and crewAI tasks."""
    found: list[dict] = []
    tool_nodes: dict[str, set[str]] = {}
    for node in ast.walk(mod.tree):
        if not isinstance(node, ast.Call):
            continue
        if last_name(node.func) == "add_node" and len(node.args) >= 2:
            label = str_const(node.args[0])
            value = mod.resolve(node.args[1])
            if label and isinstance(value, ast.Call) and last_name(value.func) == "ToolNode":
                tool_nodes[label] = symbols_in(mod, value.args[0] if value.args else kwarg(value, "tools"))
    for node in ast.walk(mod.tree):
        if not isinstance(node, ast.Call):
            continue
        for key in ("interrupt_before", "interrupt_after"):
            value = mod.resolve(kwarg(node, key))
            if not isinstance(value, (ast.List, ast.Tuple)):
                continue
            labels = {s for s in (str_const(e) for e in value.elts) if s}
            targets = set(labels)
            for label in labels:
                targets |= tool_nodes.get(label, set())
            if "tools" in labels:
                targets |= symbols_in(mod, kwarg(node, "tools") or (node.args[1] if len(node.args) > 1 else None))
            found.append({"kind": key, "targets": targets, "evidence": f"{key}={short(value)}", "file": mod.rel,
                          "line": node.lineno, "conditional": False})
        if is_hitl_wrapper(node.func):
            targets: set[str] = set()
            for part in list(node.args) + [kw.value for kw in node.keywords]:
                for sub in ast.walk(part):
                    if isinstance(sub, ast.Dict):
                        for k, v in zip(sub.keys, sub.values):
                            key_name = str_const(k)
                            if key_name and not (isinstance(v, ast.Constant) and v.value is False):
                                targets.add(key_name)
                    elif isinstance(sub, ast.Name):
                        targets.add(sub.id)
                    elif isinstance(sub, (ast.List, ast.Tuple)):
                        targets |= {s for s in (str_const(e) for e in sub.elts) if s}
            found.append({"kind": "hitl-wrapper", "targets": targets, "evidence": short(node), "file": mod.rel,
                          "line": node.lineno, "conditional": False})
        if last_name(node.func) == "Task":
            human = kwarg(node, "human_input")
            if isinstance(human, ast.Constant) and human.value is True:
                found.append({"kind": "task-human-input", "targets": symbols_in(mod, kwarg(node, "tools")),
                              "evidence": "Task(human_input=True)", "file": mod.rel, "line": node.lineno,
                              "conditional": True})
    return found


def parse_policy(path: str) -> dict[str, str]:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except OSError as exc:
        raise UsageError(f"cannot read policy {path}: {exc.strerror or exc}") from exc
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise UsageError(f"policy {path} is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise UsageError(f"policy {path} must be a JSON object of tool name to always, never or conditional")
    for key, value in data.items():
        if value not in POLICY_VALUES:
            raise UsageError(f"policy {path}: tool {key!r} has {value!r}; use always, never or conditional")
    return data


def finding(fid: str, sev: str, tool: dict | None, message: str, file: str = "", line: int = 0) -> dict:
    return {"id": fid, "severity": sev, "tool": tool["name"] if tool else "",
            "file": tool["file"] if tool else file, "line": tool["line"] if tool else line,
            "message": message, "fix": FIXES[fid]}


def judge(tools: list[dict], policy: dict[str, str]) -> list[dict]:
    out: list[dict] = []
    for t in tools:
        verbs = [w for w in words(t["name"]) if w in CONSEQUENTIAL_VERBS]
        t["name_verbs"] = verbs
        t["consequential"] = bool(t["side_effects"] or verbs)
        gates = t["gates"]
        blind = [g for g in gates if g["result_ignored"] and g["kind"] in {"input", "interrupt"}]
        effective = [g for g in gates if g["kind"] not in {"explicit-false", "not-bool"} and g not in blind]
        rule = policy.get(t["name"])
        for g in gates:
            if g["kind"] == "not-bool":
                out.append(finding("GATE-NOT-BOOL", "high", t, f"{g['evidence']} is not a bool, so whether the tool "
                                   "asks for approval depends on how the installed SDK treats that value"))
        not_bool = any(g["kind"] == "not-bool" for g in gates)
        if t["consequential"] and not effective and not not_bool and rule != "never":
            if blind:
                out.append(finding("GATE-RESULT-IGNORED", "high", t, f"{blind[0]['evidence']} at line "
                                   f"{blind[0]['line']} discards the answer, so a refusal does not stop the tool"))
            else:
                why = ", ".join(e["evidence"] for e in t["side_effects"][:2]) or f"name verb {verbs[0]!r}"
                explicit = next((g["evidence"] for g in gates if g["kind"] == "explicit-false"), "")
                out.append(finding("NO-GATE", "high", t, f"consequential ({why}) and no approval gate"
                                   + (f" ({explicit})" if explicit else "")))
        for g in effective:
            callee = g["evidence"].split("(")[0].split(".")[-1].lower()
            if g["result_ignored"] and not callee.startswith(("require", "ensure", "assert")):
                out.append(finding("GATE-RESULT-IGNORED", "medium", t, f"{g['evidence']} at line {g['line']} discards "
                                   "its result: confirm it raises when the human refuses"))
            if g["conditional"]:
                what = ("a task-level review: check it happens before the tool acts, not after the task's output"
                        if g["kind"] == "task-human-input" else "decided at run time")
                out.append(finding("GATE-CONDITIONAL", "info", t, f"{g['evidence']} is {what}; read it"))
        if not t["consequential"] and any(not g["conditional"] for g in effective) and rule != "always":
            out.append(finding("GATE-ON-READ-ONLY", "info", t, "read-only tool behind an unconditional approval"))
        if t["framework"] == "mcp":
            ann = t.get("annotations", {})
            if ann.get("readOnlyHint") is True and t["side_effects"]:
                out.append(finding("READONLY-HINT-BUT-WRITES", "medium", t, "readOnlyHint=True but the body calls "
                                   + t["side_effects"][0]["evidence"]))
            deletes = any(v in DELETE_VERBS for v in verbs) or any(is_delete_effect(e) for e in t["side_effects"])
            if deletes and ann.get("destructiveHint") is not True:
                said_false = ann.get("destructiveHint") is False
                out.append(finding("DESTRUCTIVE-NO-HINT", "medium" if said_false else "low", t,
                                   "deletes data but " + ("says destructiveHint=False" if said_false
                                                          else "does not set destructiveHint=True")))
        if rule:
            has_fixed = any(not g["conditional"] for g in effective)
            has_cond = any(g["conditional"] for g in effective)
            ok = {"always": has_fixed, "never": not effective, "conditional": has_cond}[rule]
            if not ok:
                now = "unconditional gate" if has_fixed else "conditional gate" if has_cond else "no gate"
                out.append(finding("POLICY-MISMATCH", "medium", t, f"policy says {rule!r}, code has {now}"))
    names = {t["name"] for t in tools}
    for name in sorted(set(policy) - names):
        out.append(finding("POLICY-MISMATCH", "medium", None, f"policy names {name!r}, which was not found in the code",
                           file="(policy)"))
        out[-1]["tool"] = name
    out.sort(key=lambda f: (RANK[f["severity"]], f["file"], f["line"], f["tool"], f["id"]))
    return out


def iter_files(root: Path) -> tuple[list[Path], bool]:
    if root.is_file():
        return [root], False
    files: list[Path] = []
    for path in sorted(root.rglob("*.py")):
        rel_parts = path.relative_to(root).parts
        if any(part in SKIP_DIRS for part in rel_parts[:-1]) or not path.is_file():
            continue
        if path.name.startswith("test_") or path.name.endswith("_test.py") or path.name == "conftest.py":
            continue
        if len(files) >= MAX_FILES:
            return files, True
        files.append(path)
    return files, False


def audit(root: Path, policy: dict[str, str]) -> dict:
    files, truncated = iter_files(root)
    base = root.parent if root.is_file() else root
    tools: list[dict] = []
    gates_elsewhere: list[dict] = []
    skipped: list[dict] = []
    for path in files:
        rel = path.relative_to(base).as_posix()
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                skipped.append({"file": rel, "reason": f"larger than {MAX_FILE_BYTES} bytes"})
                continue
            source = path.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=rel)
        except SyntaxError as exc:
            skipped.append({"file": rel, "reason": f"syntax error at line {exc.lineno}: {exc.msg}"})
            continue
        except UnicodeDecodeError:
            skipped.append({"file": rel, "reason": "not UTF-8"})
            continue
        except (OSError, ValueError) as exc:
            skipped.append({"file": rel, "reason": f"cannot read: {exc}"})
            continue
        mod = Module(tree, rel)
        tools += find_tools(mod)
        gates_elsewhere += project_gates(mod)
    for t in tools:
        for g in gates_elsewhere:
            if t["name"] in g["targets"] or (t["symbol"] and t["symbol"] in g["targets"]):
                t["gates"].append({k: v for k, v in g.items() if k != "targets"} | {"result_ignored": False})
    for t in tools:
        t["gates"].sort(key=lambda g: (g["file"] != t["file"], g["file"], g["line"], g["kind"]))
    tools.sort(key=lambda t: (t["file"], t["line"], t["name"]))
    findings = judge(tools, policy)
    return {
        "tool": "approval_gates",
        "files_scanned": len(files) - len(skipped),
        "truncated": truncated,
        "skipped": skipped,
        "summary": {
            "tools": len(tools),
            "consequential": sum(1 for t in tools if t["consequential"]),
            "findings": {s: sum(1 for f in findings if f["severity"] == s) for s in SEVERITIES},
        },
        "tools": tools,
        "findings": findings,
    }


def gate_label(t: dict) -> str:
    if not t["gates"]:
        return "none"
    parts = []
    for g in t["gates"]:
        where = f"{g['file']}:{g['line']}" if g["file"] != t["file"] else f"L{g['line']}"
        flag = " (conditional)" if g["conditional"] else " (answer ignored)" if g["result_ignored"] else ""
        parts.append(f"`{g['evidence']}`{flag} {where}")
    return "; ".join(parts)


def cell(text: str) -> str:
    return text.replace("|", "\\|")


def to_markdown(rep: dict, root_label: str) -> str:
    s = rep["summary"]
    counts = ", ".join(f"{n} {sev}" for sev, n in s["findings"].items() if n) or "none"
    head = (f"Files scanned: {rep['files_scanned']}. Tools: {s['tools']} ({s['consequential']} consequential). "
            f"Findings: {counts}.")
    if rep["skipped"]:
        head += f" Skipped files: {len(rep['skipped'])}."
    if rep["truncated"]:
        head += f" Stopped after {MAX_FILES} files; point the script at a subdirectory for the rest."
    out = [f"# Tool approval gate audit: `{root_label}`", "", head, "", "## Tools", ""]
    out += ["| Tool | Framework | Location | Side effects | Gate |", "|---|---|---|---|---|"]
    for t in rep["tools"]:
        fx = "; ".join(f"{e['kind']}: `{e['evidence']}` L{e['line']}" for e in t["side_effects"])
        if not fx and t["name_verbs"]:
            fx = f"name verb: {', '.join(t['name_verbs'])}"
        out.append(f"| `{cell(t['name'])}` | {t['framework']} | `{t['file']}:{t['line']}` | {cell(fx or 'read-only')} "
                   f"| {cell(gate_label(t))} |")
    if not rep["tools"]:
        out.append("| none found | | | | |")
    out += ["", "## Findings", ""]
    if rep["findings"]:
        out += ["| # | Severity | Id | Tool | Location | Finding | Fix |", "|---|---|---|---|---|---|---|"]
        for i, f in enumerate(rep["findings"], 1):
            out.append(f"| {i} | {f['severity']} | {f['id']} | `{cell(f['tool'])}` | `{f['file']}{':' + str(f['line']) if f['line'] else ''}` | "
                       f"{cell(f['message'])} | {cell(f['fix'])} |")
    else:
        out.append("No findings.")
    if rep["skipped"]:
        out += ["", "## Skipped files", ""]
        out += [f"- `{x['file']}`: {x['reason']}" for x in rep["skipped"]]
    out += ["", "Findings are leads from static rules. Read each gate in the code before signing off."]
    return "\n".join(out) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__.split("\n\n")[0],
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Exit codes: 0 no finding at or above --fail-on, 1 findings at or above --fail-on, 2 bad input or usage "
               "(missing root, bad policy, or an unparsable file with --strict).",
    )
    ap.add_argument("root", nargs="?", default=".", help="directory or Python file to audit (default .)")
    ap.add_argument("--format", choices=["markdown", "json"], default="markdown")
    ap.add_argument("--policy", help='JSON object {"tool_name": "always"|"never"|"conditional"}')
    ap.add_argument("--fail-on", choices=["high", "medium", "low"], default="high",
                    help="exit 1 when a finding is at or above this severity (default high)")
    ap.add_argument("--strict", action="store_true", help="exit 2 when a Python file cannot be parsed")
    ap.add_argument("--out", help="write the report to this file instead of stdout")
    args = ap.parse_args(argv)
    root = Path(args.root)
    try:
        if not root.exists():
            raise UsageError(f"{args.root} does not exist")
        if root.is_file() and root.suffix != ".py":
            raise UsageError(f"{args.root} is not a Python file")
        policy = parse_policy(args.policy) if args.policy else {}
    except UsageError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    rep = audit(root.resolve(), policy)
    if args.strict and rep["skipped"]:
        for x in rep["skipped"]:
            print(f"error: {x['file']}: {x['reason']}", file=sys.stderr)
        return 2
    rep = {"root": args.root.replace("\\", "/"), **rep}
    text = json.dumps(rep, indent=1) + "\n" if args.format == "json" else to_markdown(rep, rep["root"])
    try:
        if args.out:
            Path(args.out).write_text(text, encoding="utf-8")
        else:
            sys.stdout.write(text)
    except OSError as exc:
        print(f"error: cannot write output: {exc}", file=sys.stderr)
        return 2
    return int(any(RANK[f["severity"]] <= RANK[args.fail_on] for f in rep["findings"]))


if __name__ == "__main__":
    sys.exit(main())
