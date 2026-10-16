"""Tests for approval_gates.py. Every agent project is synthetic (fixtures/ and the snippets below) and is parsed,
never run."""
from __future__ import annotations

import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
FIXTURES = HERE / "fixtures"
sys.path.insert(0, str(HERE))
import approval_gates as ag  # noqa: E402


def run(*argv: str) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = ag.main(list(argv))
    return rc, out.getvalue(), err.getvalue()


def run_json(*argv: str) -> tuple[int, dict]:
    rc, out, err = run(*argv, "--format", "json")
    return rc, json.loads(out) if out else {"error": err}


def ids(rep: dict) -> list[tuple[str, str]]:
    return [(f["id"], f["tool"]) for f in rep["findings"]]


def project(source: str, name: str = "agent.py") -> tempfile.TemporaryDirectory:
    td = tempfile.TemporaryDirectory()
    (Path(td.name) / name).write_text(source, encoding="utf-8")
    return td


class GoldenTests(unittest.TestCase):
    def check(self, fixture: str, golden: str, *extra: str) -> int:
        rc, rep = run_json(str(FIXTURES / fixture), *extra)
        rep.pop("root")
        expected = json.loads((FIXTURES / "golden" / f"{golden}.json").read_text(encoding="utf-8"))
        self.assertEqual(rep, expected)
        return rc

    def test_openai_agents(self):
        self.assertEqual(self.check("openai_agents", "openai_agents"), 1)

    def test_langgraph(self):
        self.assertEqual(self.check("langgraph", "langgraph"), 1)

    def test_crewai(self):
        self.assertEqual(self.check("crewai", "crewai"), 1)

    def test_mcp_server(self):
        self.assertEqual(self.check("mcp_server", "mcp_server"), 1)

    def test_clean_project_has_no_findings(self):
        self.assertEqual(self.check("clean", "clean"), 0)

    def test_policy(self):
        self.assertEqual(self.check("openai_agents", "policy", "--policy", str(FIXTURES / "policy.json")), 1)


class FindingTests(unittest.TestCase):
    def test_framework_detection_and_key_findings(self):
        _, rep = run_json(str(FIXTURES))
        frameworks = {t["name"]: t["framework"] for t in rep["tools"]}
        self.assertEqual(frameworks["send_invoice"], "openai-agents")
        self.assertEqual(frameworks["move_files"], "langchain")
        self.assertEqual(frameworks["cleanup_cache"], "crewai")
        self.assertEqual(frameworks["purge_notes"], "mcp")
        found = ids(rep)
        for expected in [("NO-GATE", "run_tests"), ("GATE-NOT-BOOL", "delete_branch"), ("NO-GATE", "move_files"),
                         ("GATE-RESULT-IGNORED", "cleanup_cache"), ("READONLY-HINT-BUT-WRITES", "save_note"),
                         ("DESTRUCTIVE-NO-HINT", "delete_note"), ("GATE-CONDITIONAL", "send_newsletter"),
                         ("GATE-ON-READ-ONLY", "list_invoices")]:
            self.assertIn(expected, found)
        gated = {t["name"] for t in rep["tools"] if t["gates"]}
        self.assertIn("write_report", gated)  # ToolNode named in interrupt_before
        self.assertNotIn("search_docs", gated)  # in a ToolNode that is not interrupted

    def test_needs_approval_values(self):
        src = (
            "from agents import function_tool\n"
            "NEVER = False\n"
            "@function_tool(needs_approval=None)\ndef send_a(x): pass\n"
            "@function_tool(needs_approval=1)\ndef send_b(x): pass\n"
            "@function_tool(needs_approval=lambda ctx, p, c: p['n'] > 5)\ndef send_c(x): pass\n"
            "@function_tool(needs_approval=NEVER)\ndef send_d(x): pass\n"
        )
        with project(src) as td:
            _, rep = run_json(td)
        found = ids(rep)
        self.assertIn(("GATE-NOT-BOOL", "send_a"), found)
        self.assertIn(("GATE-NOT-BOOL", "send_b"), found)
        self.assertNotIn(("NO-GATE", "send_a"), found)
        self.assertIn(("GATE-CONDITIONAL", "send_c"), found)
        self.assertIn(("NO-GATE", "send_d"), found)

    def test_wrapper_and_name_rules(self):
        src = (
            "import os\n"
            "from langchain_core.tools import tool\n"
            "@tool\ndef drop_table(name: str) -> str:\n    return name\n"
            "@tool\ndef remove_user(user_id: str) -> str:\n    return user_id\n"
            "@tool\ndef send_receipt(order_id: str) -> str:\n    send_confirmation_email(order_id)\n    return 'ok'\n"
            "@tool\ndef delete_file(path: str) -> str:\n    require_human_approval(path)\n    os.remove(path)\n"
            "hitl = HumanInTheLoopMiddleware(policy={'drop_table': True, 'remove_user': False})\n"
        )
        with project(src) as td:
            _, rep = run_json(td)
        found = ids(rep)
        self.assertNotIn(("NO-GATE", "drop_table"), found)
        self.assertIn(("NO-GATE", "remove_user"), found)  # the wrapper maps it to False
        self.assertIn(("NO-GATE", "send_receipt"), found)  # a confirmation e-mail is not an approval
        self.assertNotIn(("NO-GATE", "delete_file"), found)
        self.assertNotIn(("GATE-RESULT-IGNORED", "delete_file"), found)  # require_* is taken to raise

    def test_fail_on_threshold(self):
        self.assertEqual(run(str(FIXTURES / "clean"), "--fail-on", "low")[0], 0)
        src = "from agents import function_tool\n@function_tool(needs_approval=True)\ndef get_time() -> str:\n    return 'now'\n"
        with project(src) as td:
            self.assertEqual(run(td, "--fail-on", "low")[0], 0)  # only an info finding
        with project("from mcp.server.fastmcp import FastMCP\nmcp = FastMCP('x')\n@mcp.tool(annotations={'destructiveHint': True})\n"
                     "def delete_note(n: str) -> str:\n    return n\n") as td:
            self.assertEqual(run(td, "--fail-on", "high")[0], 1)
            self.assertEqual(run(td, "--fail-on", "medium")[0], 1)


class InputTests(unittest.TestCase):
    def test_unparsable_file_is_skipped_or_strict(self):
        rc, rep = run_json(str(FIXTURES / "broken"))
        self.assertEqual(rc, 0)
        self.assertEqual([s["file"] for s in rep["skipped"]], ["bad_syntax.py"])
        self.assertTrue(rep["skipped"][0]["reason"].startswith("syntax error"))
        self.assertEqual([t["name"] for t in rep["tools"]], ["get_status"])
        rc, _, err = run(str(FIXTURES / "broken"), "--strict")
        self.assertEqual(rc, 2)
        self.assertIn("bad_syntax.py", err)

    def test_bad_usage_exits_2(self):
        self.assertEqual(run(str(FIXTURES / "does-not-exist"))[0], 2)
        self.assertEqual(run(str(FIXTURES / "policy.json"))[0], 2)  # not a Python file
        with tempfile.TemporaryDirectory() as td:
            cases = {"bad.json": "{not json", "list.json": '["send_email"]', "value.json": '{"send_email": "sometimes"}',
                     "empty.json": ""}
            for name, body in cases.items():
                path = Path(td) / name
                path.write_text(body, encoding="utf-8")
                rc, _, err = run(str(FIXTURES / "clean"), "--policy", str(path))
                self.assertEqual(rc, 2, name)
                self.assertIn("error:", err)
            self.assertEqual(run(str(FIXTURES / "clean"), "--policy", str(Path(td) / "missing.json"))[0], 2)
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as ctx:
            ag.main(["--format", "yaml"])
        self.assertEqual(ctx.exception.code, 2)

    def test_empty_inputs_and_skipped_test_files(self):
        with tempfile.TemporaryDirectory() as td:
            rc, rep = run_json(td)
            self.assertEqual((rc, rep["summary"]["tools"]), (0, 0))
            (Path(td) / "empty.py").write_text("", encoding="utf-8")
            (Path(td) / "test_agent.py").write_text("from agents import function_tool\n@function_tool\ndef delete_all(): pass\n",
                                                    encoding="utf-8")
            rc, rep = run_json(td)
            self.assertEqual((rc, rep["files_scanned"], rep["tools"]), (0, 1, []))

    def test_markdown_and_out_file(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "report.md"
            rc, stdout, _ = run(str(FIXTURES / "mcp_server"), "--out", str(out))
            self.assertEqual((rc, stdout), (1, ""))
            text = out.read_text(encoding="utf-8")
        self.assertIn("# Tool approval gate audit", text)
        self.assertIn("| `delete_note` | mcp | `server.py:24` |", text)
        self.assertIn("| 1 | high | NO-GATE | `save_note` | `server.py:17` |", text)


if __name__ == "__main__":
    unittest.main()
