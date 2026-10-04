#!/usr/bin/env python3
"""Build a file-level import graph and propose a move plan, without moving anything.

Graph: Python imports are read with ast (absolute, relative and from-imports, including src/ layouts); JS and TS
imports are read with regular expressions (import ... from, export ... from, side-effect import, require() and
dynamic import()) and relative specifiers are resolved with the usual extensions and index files. A package is
a file's directory. Test files are left out unless --include-tests is given.

Report:
  coupling          files with the highest fan-in plus fan-out
  cycles            import cycles between files (strongly connected components, with one cycle path each)
  package_cycles    cycles between packages
  wide_importers    files that import from at least --max-packages other packages
  god_modules       files imported by at least --god-fan-in files from at least three packages, with the names
                    each importing package uses (the split lines a human can follow)
  moves             the move plan for --goal: file, from, to, reason, blast radius (number of importers whose
                    imports change), and the cross-package edge count before and after the whole plan
  commands          the git mv commands for the plan. They are printed, never executed.

Goals:
  split       move files whose importers all sit in one other package into that package; list god modules to
              split by hand
  merge       fold small packages (at most --small files) whose outside importers are all in one package, and
              packages that import each other, into the larger side
  boundaries  move a file when at least half of its edges (imports plus importers) go to one other package, more
              than stay in its own, and the move lowers the cross-package edge count

Reads files only; runs nothing. Exit codes: 0 ok, 1 with --fail-on-cycles when a cycle exists, 2 bad input.
"""
from __future__ import annotations

import argparse
import ast
import json
import os
import re
import shlex
import sys
from pathlib import Path, PurePosixPath

SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", ".venv", "venv", "env", "dist", "build", "__pycache__", ".tox",
    ".mypy_cache", ".ruff_cache", ".pytest_cache", "target", ".next", ".cache", "coverage", "vendor",
}
PY_EXT = {".py"}
JS_EXT = [".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"]
MAX_FILE_BYTES = 1_000_000
TEST_RE = re.compile(
    r"(^|/)(tests?|__tests__|spec)/|(^|/)test_[^/]+\.py$|_test\.py$|(^|/)conftest\.py$|\.(test|spec)\.[jt]sx?$")
JS_IMPORT_RES = [
    re.compile(r"\bimport\s+(?:type\s+)?([\w*${}\s,]+?)\s+from\s+['\"]([^'\"]+)['\"]"),
    re.compile(r"\bexport\s+(?:type\s+)?([\w*${}\s,]+?)\s+from\s+['\"]([^'\"]+)['\"]"),
    re.compile(r"\bimport\s+()['\"]([^'\"]+)['\"]"),
    re.compile(r"\brequire\(\s*()['\"]([^'\"]+)['\"]\s*\)"),
    re.compile(r"\bimport\(\s*()['\"]([^'\"]+)['\"]\s*\)"),
]


def package_of(rel: str) -> str:
    parent = PurePosixPath(rel).parent.as_posix()
    return "." if parent in {"", "."} else parent


class Graph:
    def __init__(self, root: Path, include_tests: bool) -> None:
        self.root = root
        self.files: list[str] = []
        self.edges: dict[str, dict[str, set[str]]] = {}  # importer -> target -> imported names
        self.external: dict[str, set[str]] = {}
        self.lines: dict[str, int] = {}
        self.skipped: list[str] = []
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
            for f in sorted(filenames):
                rel = (Path(dirpath) / f).relative_to(root).as_posix()
                suffix = PurePosixPath(f).suffix
                if suffix not in PY_EXT and suffix not in JS_EXT or rel.endswith(".d.ts"):
                    continue
                if not include_tests and TEST_RE.search(rel):
                    continue
                self.files.append(rel)
        self.fileset = set(self.files)
        self.modules = self._python_modules()
        for rel in self.files:
            text = self._read(rel)
            if text is None:
                self.skipped.append(rel)
                continue
            self.lines[rel] = text.count("\n") + 1
            self.edges.setdefault(rel, {})
            self.external.setdefault(rel, set())
            if rel.endswith(".py"):
                self._python(rel, text)
            else:
                self._js(rel, text)

    def _read(self, rel: str) -> str | None:
        p = self.root / rel
        try:
            if p.stat().st_size > MAX_FILE_BYTES:
                return None
            return p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None

    def _python_modules(self) -> dict[str, str]:
        mods: dict[str, str] = {}
        for rel in self.files:
            if not rel.endswith(".py"):
                continue
            parts = list(PurePosixPath(rel).with_suffix("").parts)
            if parts[-1] == "__init__":
                parts = parts[:-1]
            if not parts:
                continue
            mods.setdefault(".".join(parts), rel)
            if parts[0] in {"src", "lib"} and len(parts) > 1:
                mods.setdefault(".".join(parts[1:]), rel)
        return mods

    def _module_name(self, rel: str) -> list[str]:
        parts = list(PurePosixPath(rel).with_suffix("").parts)
        if parts[0] in {"src", "lib"} and len(parts) > 1 and ".".join(parts[1:]) in self.modules:
            parts = parts[1:]
        return parts

    def _add(self, src: str, target: str, names: set[str]) -> None:
        if target != src:
            self.edges[src].setdefault(target, set()).update(names)

    def _resolve_py(self, dotted: str) -> tuple[str | None, str]:
        parts = dotted.split(".")
        for n in range(len(parts), 0, -1):
            cand = ".".join(parts[:n])
            if cand in self.modules:
                return self.modules[cand], ".".join(parts[n:])
        return None, ""

    def _python(self, rel: str, text: str) -> None:
        try:
            tree = ast.parse(text)
        except (SyntaxError, ValueError):
            self.skipped.append(rel)
            return
        me = self._module_name(rel)
        is_pkg = rel.endswith("__init__.py")
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    target, rest = self._resolve_py(alias.name)
                    if target:
                        self._add(rel, target, {rest} if rest else set())
                    else:
                        self.external[rel].add(alias.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom):
                if node.level:
                    base = me if is_pkg else me[:-1]
                    if node.level > 1:
                        base = base[: len(base) - (node.level - 1)] if node.level - 1 <= len(base) else []
                    if base and base[-1] == "__init__":
                        base = base[:-1]
                    dotted = ".".join(base + ([node.module] if node.module else []))
                else:
                    dotted = node.module or ""
                if not dotted:
                    continue
                for alias in node.names:
                    sub, _ = self._resolve_py(f"{dotted}.{alias.name}")
                    owner, _ = self._resolve_py(dotted)
                    if sub and sub != owner and f"{dotted}.{alias.name}" in self.modules:
                        self._add(rel, sub, set())
                    elif owner:
                        self._add(rel, owner, {alias.name} if alias.name != "*" else {"*"})
                    elif not node.level:
                        self.external[rel].add(dotted.split(".")[0])

    def _resolve_js(self, rel: str, spec: str) -> str | None:
        base = PurePosixPath(rel).parent
        joined = os.path.normpath((base / spec).as_posix()).replace(os.sep, "/")
        if joined.startswith(".."):
            return None
        cands = [joined]
        stem, ext = os.path.splitext(joined)
        if ext in {".js", ".jsx", ".mjs", ".cjs"}:
            cands += [stem + e for e in (".ts", ".tsx", ".mts", ".cts")]
        cands += [joined + e for e in JS_EXT] + [f"{joined}/index{e}" for e in JS_EXT]
        return next((c for c in cands if c in self.fileset), None)

    def _js(self, rel: str, text: str) -> None:
        text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
        text = re.sub(r"(?m)^\s*//.*$", "", text)
        for rx in JS_IMPORT_RES:
            for m in rx.finditer(text):
                clause, spec = m.group(1), m.group(2)
                names = set(re.findall(r"[\w$]+", re.sub(r"\bas\s+[\w$]+", "", clause.split("{", 1)[1])) if "{"
                            in clause else set())
                if spec.startswith("."):
                    target = self._resolve_js(rel, spec)
                    if target:
                        self._add(rel, target, names)
                else:
                    ext = "/".join(spec.split("/")[:2]) if spec.startswith("@") else spec.split("/")[0]
                    self.external[rel].add(ext)

    # metrics -------------------------------------------------------------------------------------------------

    def importers(self) -> dict[str, set[str]]:
        inv: dict[str, set[str]] = {f: set() for f in self.edges}
        for src, targets in self.edges.items():
            for t in targets:
                inv.setdefault(t, set()).add(src)
        return inv


def tarjan(nodes: list[str], succ: dict[str, set[str]]) -> list[list[str]]:
    index: dict[str, int] = {}
    low: dict[str, int] = {}
    stack: list[str] = []
    on: set[str] = set()
    out: list[list[str]] = []
    counter = [0]

    def strong(v: str) -> None:
        work = [(v, iter(sorted(succ.get(v, ()))))]
        index[v] = low[v] = counter[0]
        counter[0] += 1
        stack.append(v)
        on.add(v)
        while work:
            node, it = work[-1]
            advanced = False
            for w in it:
                if w not in index:
                    index[w] = low[w] = counter[0]
                    counter[0] += 1
                    stack.append(w)
                    on.add(w)
                    work.append((w, iter(sorted(succ.get(w, ())))))
                    advanced = True
                    break
                if w in on:
                    low[node] = min(low[node], index[w])
            if advanced:
                continue
            work.pop()
            if work:
                low[work[-1][0]] = min(low[work[-1][0]], low[node])
            if low[node] == index[node]:
                comp = []
                while True:
                    w = stack.pop()
                    on.discard(w)
                    comp.append(w)
                    if w == node:
                        break
                if len(comp) > 1:
                    out.append(sorted(comp))

    for v in sorted(nodes):
        if v not in index:
            strong(v)
    return sorted(out)


def cycle_path(comp: list[str], succ: dict[str, set[str]]) -> list[str]:
    members = set(comp)
    start = comp[0]
    prev: dict[str, str] = {}
    queue = [start]
    seen = {start}
    while queue:
        node = queue.pop(0)
        for w in sorted(succ.get(node, ())):
            if w == start:
                path = [node]
                while path[-1] != start:
                    path.append(prev[path[-1]])
                return list(reversed(path)) + [start]
            if w in members and w not in seen:
                seen.add(w)
                prev[w] = node
                queue.append(w)
    return comp


def cross_edges(edges: dict[str, dict[str, set[str]]], location: dict[str, str]) -> int:
    return sum(1 for s, ts in edges.items() for t in ts if location[s] != location[t])


def plan(g: Graph, goal: str, small: int) -> tuple[list[dict], dict[str, str]]:
    inv = g.importers()
    pkg = {f: package_of(f) for f in g.edges}
    files_in: dict[str, list[str]] = {}
    for f, p in pkg.items():
        files_in.setdefault(p, []).append(f)
    movable = {f for f in g.edges if PurePosixPath(f).name not in {"__init__.py", "__main__.py"}
               and not re.match(r"index\.[cm]?[jt]sx?$", PurePosixPath(f).name)}
    location = dict(pkg)
    moves: list[dict] = []

    def move(f: str, to: str, reason: str) -> None:
        location[f] = to
        moves.append({"file": f, "from": pkg[f], "to": to, "reason": reason, "blast_radius": len(inv.get(f, ())),
                      "importers": sorted(inv.get(f, ()))})

    if goal == "split":
        for f in sorted(movable):
            users = {pkg[i] for i in inv.get(f, ())}
            if len(users) != 1:
                continue
            (target,) = users
            if target == pkg[f]:
                continue
            same_pkg_deps = [t for t in g.edges[f] if pkg[t] == pkg[f]]
            sibling_users = [i for i in inv.get(f, ()) if pkg[i] == pkg[f]]
            if same_pkg_deps or sibling_users:
                continue
            move(f, target, f"only imported from {target}; nothing in {pkg[f]} uses it")
    elif goal == "merge":
        done: set[str] = set()
        directed = {(pkg[s], pkg[t]) for s, ts in g.edges.items() for t in ts if pkg[s] != pkg[t]}
        mutual = sorted({tuple(sorted(pair)) for pair in directed if (pair[1], pair[0]) in directed})
        for a, b in mutual:
            if a in done or b in done:
                continue
            smaller, larger = sorted((a, b), key=lambda p: (len(files_in[p]), p))
            for f in sorted(files_in[smaller]):
                if f in movable:
                    move(f, larger, f"{smaller} and {larger} import each other; fold {smaller} into {larger}")
            done |= {a, b}
        for p in sorted(files_in):
            if p in done or p == "." or len(files_in[p]) > small:
                continue
            outside = {pkg[i] for f in files_in[p] for i in inv.get(f, ()) if pkg[i] != p}
            if len(outside) == 1:
                (target,) = outside
                if target in done:
                    continue
                for f in sorted(files_in[p]):
                    if f in movable:
                        move(f, target, f"{p} has {len(files_in[p])} file(s), all used only from {target}")
                done.add(p)
    else:  # boundaries
        for f in sorted(movable):
            counts: dict[str, int] = {}
            for t in g.edges[f]:
                counts[pkg[t]] = counts.get(pkg[t], 0) + 1
            for i in inv.get(f, ()):
                counts[pkg[i]] = counts.get(pkg[i], 0) + 1
            own = counts.get(pkg[f], 0)
            best = max(sorted(counts), key=lambda p: counts[p], default=None)
            total = sum(counts.values())
            if best is None or best == pkg[f] or counts[best] <= own or counts[best] * 2 < total:
                continue
            trial = dict(location)
            trial[f] = best
            if cross_edges(g.edges, trial) < cross_edges(g.edges, location):
                move(f, best, f"{counts[best]} of its {sum(counts.values())} edges go to {best}, {own} stay in "
                              f"{pkg[f]}")
    return moves, location


def commands(root: Path, moves: list[dict]) -> list[str]:
    out: list[str] = []
    made: set[str] = set()
    taken: set[str] = set()
    for m in moves:
        name = PurePosixPath(m["file"]).name
        dest = name if m["to"] == "." else f"{m['to']}/{name}"
        if (root / dest).exists() or dest in taken:
            src_pkg = PurePosixPath(m["from"]).name or "root"
            dest = f"{m['to']}/{src_pkg}/{name}" if m["to"] != "." else f"{src_pkg}/{name}"
            m["note"] = f"{name} already exists in {m['to']}; placed under {PurePosixPath(dest).parent}"
        taken.add(dest)
        m["dest"] = dest
        parent = PurePosixPath(dest).parent.as_posix()
        if parent not in {".", ""} and not (root / parent).is_dir() and parent not in made:
            out.append(f"mkdir -p {shlex.quote(parent)}")
            made.add(parent)
        out.append(f"git mv {shlex.quote(m['file'])} {shlex.quote(dest)}")
    return out


def analyse(root: Path, goal: str, top: int, max_packages: int, god_fan_in: int, small: int,
            include_tests: bool) -> dict:
    g = Graph(root, include_tests)
    inv = g.importers()
    pkg = {f: package_of(f) for f in g.edges}
    succ = {f: set(ts) for f, ts in g.edges.items()}
    coupling = sorted(({"file": f, "fan_in": len(inv.get(f, ())), "fan_out": len(g.edges[f]),
                        "external": len(g.external.get(f, ())), "lines": g.lines.get(f, 0)} for f in g.edges),
                      key=lambda r: (-(r["fan_in"] + r["fan_out"]), r["file"]))
    cycles = [{"files": c, "path": cycle_path(c, succ)} for c in tarjan(list(g.edges), succ)]
    psucc: dict[str, set[str]] = {}
    for s, ts in g.edges.items():
        for t in ts:
            if pkg[s] != pkg[t]:
                psucc.setdefault(pkg[s], set()).add(pkg[t])
    package_cycles = [{"packages": c, "path": cycle_path(c, psucc)}
                      for c in tarjan(sorted(set(pkg.values())), psucc)]
    wide = []
    for f in sorted(g.edges):
        others = sorted({pkg[t] for t in g.edges[f]} - {pkg[f]})
        if len(others) >= max_packages:
            wide.append({"file": f, "packages": others, "count": len(others)})
    gods = []
    for f in sorted(g.edges):
        users = inv.get(f, set())
        upk = {pkg[i] for i in users}
        if len(users) >= god_fan_in and len(upk) >= 3:
            groups: dict[str, set[str]] = {}
            for i in users:
                groups.setdefault(pkg[i], set()).update(g.edges[i][f])
            gods.append({"file": f, "fan_in": len(users), "importer_packages": len(upk),
                         "lines": g.lines.get(f, 0),
                         "names_by_package": {p: sorted(n) for p, n in sorted(groups.items())}})
    moves, location = plan(g, goal, small)
    cmds = commands(root, moves)
    before = cross_edges(g.edges, pkg)
    after = cross_edges(g.edges, location)
    ext_counts: dict[str, int] = {}
    for deps in g.external.values():
        for d in deps:
            ext_counts[d] = ext_counts.get(d, 0) + 1
    return {
        "repo": str(root), "goal": goal,
        "summary": {"files": len(g.edges), "edges": sum(len(t) for t in g.edges.values()),
                    "packages": len(set(pkg.values())), "cross_package_edges": before,
                    "cross_package_edges_after_plan": after, "unparsed_files": sorted(set(g.skipped))},
        "coupling": coupling[:top],
        "cycles": cycles,
        "package_cycles": package_cycles,
        "wide_importers": wide,
        "god_modules": gods,
        "external_packages": dict(sorted(ext_counts.items(), key=lambda kv: (-kv[1], kv[0]))[:top]),
        "moves": moves,
        "commands": cmds,
        "executed": False,
    }


def render(rep: dict) -> str:
    s = rep["summary"]
    out = [f"Restructure plan ({rep['goal']}): {rep['repo']}",
           f"{s['files']} files, {s['edges']} internal import edges, {s['packages']} packages, "
           f"{s['cross_package_edges']} cross-package edges", ""]
    out.append("Highest coupling (fan-in + fan-out):")
    for r in rep["coupling"]:
        out.append(f"  {r['fan_in']:>3} in {r['fan_out']:>3} out  {r['file']}")
    out.append("")
    out.append(f"File cycles ({len(rep['cycles'])}):")
    for c in rep["cycles"]:
        out.append("  " + " -> ".join(c["path"]))
    out.append(f"Package cycles ({len(rep['package_cycles'])}):")
    for c in rep["package_cycles"]:
        out.append("  " + " -> ".join(c["path"]))
    out.append("")
    out.append("Files importing from many packages:")
    for w in rep["wide_importers"] or [{"file": "none", "count": 0, "packages": []}]:
        out.append(f"  {w['file']} ({w['count']}: {', '.join(w['packages'])})")
    out.append("God modules (split by hand along these lines):")
    for gm in rep["god_modules"] or []:
        out.append(f"  {gm['file']}: {gm['fan_in']} importers from {gm['importer_packages']} packages")
        for p, names in gm["names_by_package"].items():
            out.append(f"    {p}: {', '.join(names) or '(whole module)'}")
    if not rep["god_modules"]:
        out.append("  none")
    out.append("")
    out.append("| File | From | To | Reason | Blast radius |")
    out.append("|---|---|---|---|---|")
    for m in rep["moves"]:
        out.append(f"| {m['file']} | {m['from']} | {m['to']} | {m['reason']} | {m['blast_radius']} |")
    if not rep["moves"]:
        out.append("| (no moves for this goal) | | | | |")
    out.append("")
    out.append(f"Cross-package edges: {s['cross_package_edges']} now, {s['cross_package_edges_after_plan']} after "
               f"the plan")
    out.append("")
    out.append("Commands (not executed; review, run on a branch, then fix imports and run the tests):")
    out += [f"  {c}" for c in rep["commands"]] or ["  (none)"]
    if s["unparsed_files"]:
        out.append("")
        out.append("Not parsed: " + ", ".join(s["unparsed_files"]))
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="restructure_plan.py",
                                 description="Import graph, coupling, cycles and a git mv plan (printed, never run).")
    ap.add_argument("repo", help="repository root")
    ap.add_argument("--goal", choices=["split", "merge", "boundaries"], default="boundaries",
                    help="what the move plan optimises for (default: boundaries)")
    ap.add_argument("--top", type=int, default=10, help="rows in the coupling list (default: 10)")
    ap.add_argument("--max-packages", type=int, default=4,
                    help="flag files importing from at least this many other packages (default: 4)")
    ap.add_argument("--god-fan-in", type=int, default=5,
                    help="importer count from which a file shared by three or more packages is a god module "
                         "(default: 5)")
    ap.add_argument("--small", type=int, default=2, help="package size the merge goal folds away (default: 2)")
    ap.add_argument("--include-tests", action="store_true", help="include test files in the graph")
    ap.add_argument("--fail-on-cycles", action="store_true", help="exit 1 when any file cycle exists")
    ap.add_argument("--json", action="store_true", help="print JSON")
    ap.add_argument("--out", metavar="FILE", help="also write the JSON to FILE")
    args = ap.parse_args(argv)
    root = Path(args.repo).resolve()
    if not root.is_dir():
        print(f"error: not a directory: {args.repo}", file=sys.stderr)
        return 2
    rep = analyse(root, args.goal, max(1, args.top), max(1, args.max_packages), max(1, args.god_fan_in),
                  max(1, args.small), args.include_tests)
    if args.out:
        Path(args.out).write_text(json.dumps(rep, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(rep, indent=2) if args.json else render(rep))
    return 1 if args.fail_on_cycles and rep["cycles"] else 0


if __name__ == "__main__":
    sys.exit(main())
