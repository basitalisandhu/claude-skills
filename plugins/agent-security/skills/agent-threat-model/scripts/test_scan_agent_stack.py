"""Tests for scan_agent_stack.py: the draft must satisfy the agent-threat-model schema constraints, and when the
`atm` CLI is available (installed, or the sibling checkout's venv) the draft must pass `atm validate`."""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import scan_agent_stack as sas  # noqa: E402

ATM_CANDIDATES = [shutil.which("atm"), os.environ.get("ATM_BIN"), "/home/user/Github-fix/repos/agent-threat-model/.venv/bin/atm"]
ATM = next((c for c in ATM_CANDIDATES if c and Path(c).exists()), None)


def make_fixture(root: Path) -> None:
    (root / "requirements.txt").write_text("langchain==0.3.0\nopenai\nchromadb\npsycopg2\n")
    (root / "agent.py").write_text(
        "import os, subprocess, smtplib, imaplib\nfrom langchain_core.tools import tool\nimport chromadb\n"
        "KEY = os.environ['OPENAI_API_KEY']\n@tool\ndef run(cmd):\n    return subprocess.run(cmd, shell=True)\n"
        "def mail():\n    smtplib.SMTP('x').send_message(None)\n# requires_approval before send; rate_limit 10/min\n"
    )
    (root / ".mcp.json").write_text(json.dumps({"mcpServers": {"gh": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"], "env": {"GITHUB_TOKEN": "${GITHUB_TOKEN}"}},
                                                               "fs": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem@0.6.2", "/tmp"]}}}))
    (root / "node_modules").mkdir()
    (root / "node_modules" / "x.py").write_text("import crewai")


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
            out.write_text(sas.to_yaml(sas.build_model(root, sas.detect(root))))
            proc = subprocess.run([ATM, "validate", str(out)], capture_output=True, text=True, timeout=120)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertIn("ok:", proc.stdout)
            empty = root / "empty"; empty.mkdir()
            out2 = root / "empty.yaml"
            out2.write_text(sas.to_yaml(sas.build_model(empty, sas.detect(empty))))
            proc = subprocess.run([ATM, "validate", str(out2)], capture_output=True, text=True, timeout=120)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)


if __name__ == "__main__":
    unittest.main()
