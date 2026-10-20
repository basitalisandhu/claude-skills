"""Tests for scan_agent_stack.py: the draft must satisfy the agent-threat-model schema constraints, and when the
`atm` CLI is available (installed, or the sibling checkout's venv) the draft must pass `atm validate`."""
from __future__ import annotations

import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import scan_agent_stack as sas  # noqa: E402

# atm on PATH, an explicit ATM_BIN, or a sibling checkout of agent-threat-model next to this repository
ATM_CANDIDATES = [shutil.which("atm"), os.environ.get("ATM_BIN"), str(HERE.parents[5] / "agent-threat-model" / ".venv" / "bin" / "atm")]
ATM = next((c for c in ATM_CANDIDATES if c and Path(c).exists()), None)


def make_fixture(root: Path) -> None:
    (root / "requirements.txt").write_text("langchain==0.3.0\nopenai\nchromadb\npsycopg2\n", encoding="utf-8")
    (root / "agent.py").write_text(
        "import os, subprocess, smtplib, imaplib\nfrom langchain_core.tools import tool\nimport chromadb\n"
        "KEY = os.environ['OPENAI_API_KEY']\n@tool\ndef run(cmd):\n    return subprocess.run(cmd, shell=True)\n"
        "def mail():\n    smtplib.SMTP('x').send_message(None)\n# requires_approval before send; rate_limit 10/min\n", encoding="utf-8"
    )
    (root / ".mcp.json").write_text(json.dumps({"mcpServers": {"gh": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"], "env": {"GITHUB_TOKEN": "${GITHUB_TOKEN}"}},
                                                               "fs": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem@0.6.2", "/tmp"]}}}), encoding="utf-8")
    (root / "node_modules").mkdir()
    (root / "node_modules" / "x.py").write_text("import crewai", encoding="utf-8")


def check_schema_shape(tc: unittest.TestCase, model: dict) -> None:
    tc.assertEqual(set(model), {"system", "principals", "agents", "channels", "tools", "data_stores", "controls"})
    tc.assertTrue(model["system"]["name"])
    tc.assertGreaterEqual(len(model["agents"]), 1)
    ids: list[str] = []
    for section in ("principals", "agents", "channels", "tools", "data_stores"):
        for item in model[section]:
            tc.assertRegex(item["id"], sas.ID_RE.pattern)
            tc.assertLessEqual(len(item["id"]), 64)
            ids.append(item["id"])
    tc.assertEqual(len(ids), len(set(ids)), "ids must be unique across element types")
    channel_ids = {c["id"] for c in model["channels"]}
    tool_ids = {t["id"] for t in model["tools"]}
    agent_ids = {a["id"] for a in model["agents"]}
    store_ids = {s["id"] for s in model["data_stores"]}
    for p in model["principals"]:
        tc.assertIn(p["kind"], {"human", "service"}); tc.assertIn(p["trust"], sas.TRUST)
        tc.assertTrue(set(p.get("channels", [])) <= channel_ids)
    for a in model["agents"]:
        tc.assertIn(a["autonomy"], sas.AUTONOMY); tc.assertIn(a.get("memory", "none"), sas.MEMORY)
        tc.assertTrue(set(a.get("inputs", [])) <= channel_ids); tc.assertTrue(set(a.get("tools", [])) <= tool_ids)
        tc.assertTrue(set(a.get("delegates_to", [])) <= agent_ids)
    for c in model["channels"]:
        tc.assertIn(c["kind"], sas.CHANNEL_KINDS); tc.assertIn(c["origin"], sas.CHANNEL_ORIGINS); tc.assertIsInstance(c["trusted"], bool)
    for t in model["tools"]:
        tc.assertIn(t["kind"], sas.TOOL_KINDS); tc.assertIn(t["auth"], sas.TOOL_AUTH); tc.assertIn(t.get("approval", "none"), sas.APPROVALS)
        tc.assertIn(t.get("provider", "first-party"), {"first-party", "third-party"})
        tc.assertTrue(set(t.get("data_stores", [])) <= store_ids)
        tc.assertTrue(set(t) <= {"id", "kind", "target", "scope", "auth", "approval", "sandboxed", "provider", "pinned", "data_stores", "description"})
    for s in model["data_stores"]:
        tc.assertIn(s["sensitivity"], sas.SENSITIVITY)
    for ctl in model["controls"]:
        tc.assertIn(ctl, sas.CONTROL_IDS)


class ScanTests(unittest.TestCase):
    def test_detections(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            make_fixture(root)
            d = sas.detect(root)
            self.assertIn("langchain", d["hits"]["frameworks"])
            self.assertIn("mcp", d["hits"]["frameworks"])
            self.assertNotIn("crewai", d["hits"]["frameworks"])
            self.assertIn("openai", d["hits"]["providers"])
            self.assertIn("shell/exec", d["hits"]["authorities"])
            self.assertIn("send-message", d["hits"]["authorities"])
            self.assertIn("email", d["hits"]["inputs"])
            self.assertIn("vector", d["hits"]["stores"])
            self.assertIn("OPENAI_API_KEY", d["credentials"])
            names = {s["name"]: s for s in d["mcp_servers"]}
            self.assertFalse(names["gh"]["pinned"]); self.assertTrue(names["gh"]["has_env_secret"])
            self.assertTrue(names["fs"]["pinned"])
            self.assertTrue(d["signals"]["approval"]); self.assertTrue(d["signals"]["limits"])

    def test_model_matches_schema_shape(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            make_fixture(root)
            model = sas.build_model(root, sas.detect(root))
            check_schema_shape(self, model)
            tools = {t["id"]: t for t in model["tools"]}
            self.assertEqual(tools["shell-exec"]["kind"], "exec")
            self.assertEqual(tools["send-message"]["kind"], "messaging")
            self.assertEqual(tools["send-message"]["auth"], "static-key")
            self.assertEqual(tools["mcp-gh"]["provider"], "third-party"); self.assertFalse(tools["mcp-gh"]["pinned"]); self.assertEqual(tools["mcp-gh"]["kind"], "write")
            self.assertTrue(tools["mcp-fs"]["pinned"])
            channels = {c["id"]: c for c in model["channels"]}
            self.assertEqual(channels["email-in"]["kind"], "email"); self.assertFalse(channels["email-in"]["trusted"])
            self.assertEqual(channels["rag-index"]["kind"], "rag")
            self.assertEqual(model["agents"][0]["autonomy"], "act-with-approval")
            self.assertIn("rate-limiting", model["controls"]); self.assertIn("approval-gates", model["controls"])
            low = [p for p in model["principals"] if p["trust"] == "low"]
            self.assertTrue(low and "email-in" in low[0]["channels"])

    def test_empty_repo_still_valid(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            model = sas.build_model(root, sas.detect(root))
            check_schema_shape(self, model)
            self.assertEqual(model["agents"][0]["autonomy"], "act")
            self.assertEqual(model["tools"], [])
            y = sas.to_yaml(model)
            self.assertIn("tools: []", y); self.assertIn("controls: []", y)

    def test_yaml_scalars(self):
        self.assertEqual(sas.scalar("shell-exec"), "shell-exec")
        self.assertEqual(sas.scalar("hosted LLM"), "hosted LLM")
        self.assertEqual(sas.scalar("yes"), '"yes"')
        self.assertEqual(sas.scalar("a: b"), '"a: b"')
        self.assertEqual(sas.scalar(True), "true")
        self.assertEqual(sas.scalar("0.0.0.0:80"), '"0.0.0.0:80"')

    @unittest.skipUnless(ATM, "atm CLI not available")
    def test_atm_validate_accepts_the_draft(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            make_fixture(root)
            out = root / "system.yaml"
            out.write_text(sas.to_yaml(sas.build_model(root, sas.detect(root))), encoding="utf-8")
            proc = subprocess.run([ATM, "validate", str(out)], capture_output=True, text=True, timeout=120)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertIn("ok:", proc.stdout)
            empty = root / "empty"; empty.mkdir()
            out2 = root / "empty.yaml"
            out2.write_text(sas.to_yaml(sas.build_model(empty, sas.detect(empty))), encoding="utf-8")
            proc = subprocess.run([ATM, "validate", str(out2)], capture_output=True, text=True, timeout=120)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)


class RobustnessTests(unittest.TestCase):
    def run_main(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = sas.main(argv)
        return rc, out.getvalue(), err.getvalue()

    def test_missing_root_exits_2(self):
        with tempfile.TemporaryDirectory() as td:
            rc, out, err = self.run_main([str(Path(td) / "nope")])
            self.assertEqual(rc, 2); self.assertEqual(out, ""); self.assertIn("is not a directory", err)
            f = Path(td) / "file.py"; f.write_text("x = 1\n", encoding="utf-8")
            self.assertEqual(self.run_main([str(f)])[0], 2)

    def test_unwritable_out_exits_2(self):
        with tempfile.TemporaryDirectory() as td:
            rc, _, err = self.run_main([td, "--out", str(Path(td) / "no" / "such" / "system.yaml")])
            self.assertEqual(rc, 2); self.assertIn("cannot write", err)

    def test_out_writes_yaml_and_hint(self):
        with tempfile.TemporaryDirectory() as td:
            make_fixture(Path(td))
            out = Path(td) / "system.yaml"
            rc, stdout, err = self.run_main([td, "--out", str(out)])
            self.assertEqual(rc, 0); self.assertEqual(stdout, "")
            self.assertIn("next: atm validate", err)
            self.assertTrue(out.read_text(encoding="utf-8").startswith("# Draft written by scan_agent_stack.py"))

    def test_malformed_mcp_entries_do_not_drop_good_servers(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / ".mcp.json").write_text(json.dumps({"mcpServers": {
                "broken": "npx some-server", "nullcmd": {"command": None, "args": "--flag"},
                "good": {"command": "uvx", "args": ["mcp-server-fetch==2025.4.7"], "env": {"API_TOKEN": "${API_TOKEN}"}}}}), encoding="utf-8")
            (root / "cursor").mkdir()
            (root / "cursor" / "mcp.json").write_text("{not json", encoding="utf-8")
            d = sas.detect(root)
            names = {s["name"]: s for s in d["mcp_servers"]}
            self.assertEqual(set(names), {"nullcmd", "good"})
            self.assertTrue(names["good"]["pinned"]); self.assertTrue(names["good"]["has_env_secret"])
            self.assertTrue(any("'broken' is not an object" in n for n in d["notes"]), d["notes"])
            self.assertTrue(any("cursor/mcp.json: not valid JSON" in n for n in d["notes"]), d["notes"])
            check_schema_shape(self, sas.build_model(root, d))

    def test_vscode_servers_block_and_http_transport(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); (root / ".vscode").mkdir()
            (root / ".vscode" / "mcp.json").write_text(json.dumps({"servers": {"docs": {"type": "http", "url": "https://mcp.example.com/mcp"}}}), encoding="utf-8")
            d = sas.detect(root)
            self.assertEqual(d["mcp_servers"][0]["transport"], "http"); self.assertTrue(d["mcp_servers"][0]["pinned"])
            self.assertEqual(d["mcp_servers"][0]["target"], "https://mcp.example.com/mcp")

    def test_checkout_inside_a_folder_named_build(self):
        # skip folders apply inside the scanned tree only, not to the folders above it
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "build" / "agent"
            root.mkdir(parents=True)
            make_fixture(root)
            d = sas.detect(root)
            self.assertIn("langchain", d["hits"]["frameworks"])
            self.assertEqual({s["name"] for s in d["mcp_servers"]}, {"gh", "fs"})

    def test_walk_limit_is_reported(self):
        old = sas.MAX_FILES
        sas.MAX_FILES = 2
        try:
            with tempfile.TemporaryDirectory() as td:
                for i in range(4):
                    (Path(td) / f"m{i}.py").write_text("x = 1\n", encoding="utf-8")
                self.assertTrue(sas.detect(Path(td))["truncated"])
                rc, _, err = self.run_main([td])
                self.assertEqual(rc, 0); self.assertIn("stopped after 2 files", err)
        finally:
            sas.MAX_FILES = old


if __name__ == "__main__":
    unittest.main()
