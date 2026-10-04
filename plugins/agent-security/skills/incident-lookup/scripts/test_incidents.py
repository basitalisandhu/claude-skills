"""Tests for incidents.py. No network: every test uses --offline, --data, or a dead fetch URL."""
from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import incidents  # noqa: E402

REQUIRED = ["id", "date", "name", "type", "lens", "vector", "channel_in", "authority", "channel_out", "adversarial", "outcome",
            "cve", "sources", "summary", "mappings", "affected", "tags", "status"]


def run(argv: list[str]) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        try:
            rc = incidents.main(argv)
        except SystemExit as exc:
            rc = int(exc.code or 0)
    return rc, out.getvalue(), err.getvalue()


class BundledDataTests(unittest.TestCase):
    def test_bundle_is_an_array_of_schema_shaped_records(self):
        data = json.loads(incidents.BUNDLED.read_text(encoding="utf-8"))
        self.assertIsInstance(data, list)
        self.assertGreaterEqual(len(data), 80)
        ids = [e["id"] for e in data]
        self.assertEqual(ids, sorted(ids)); self.assertEqual(len(ids), len(set(ids)))
        for e in data:
            self.assertEqual(set(e), set(REQUIRED), e["id"])
            self.assertRegex(e["date"], r"^\d{4}-\d{2}(-\d{2})?$")
            self.assertIsInstance(e["cve"], list); self.assertIsInstance(e["adversarial"], bool)
            self.assertTrue(e["sources"] and e["sources"][0]["url"].startswith("https://"))
            self.assertEqual(set(e["mappings"]), {"owasp_agentic", "owasp_llm", "mitre_atlas"})
            self.assertEqual(set(e["affected"]), {"vendors", "products", "frameworks"})
            self.assertIn(e["status"], {"confirmed", "reported", "disputed"})

    def test_controls_cover_every_vector(self):
        data = json.loads(incidents.BUNDLED.read_text(encoding="utf-8"))
        for v in {e["vector"] for e in data}:
            self.assertIn(v, incidents.CONTROLS, f"no controls text for vector {v}")


class ListTests(unittest.TestCase):
    def test_list_all_offline(self):
        rc, out, err = run(["--offline", "--format", "json", "list"])
        self.assertEqual(rc, 0)
        rows = json.loads(out)
        self.assertGreaterEqual(len(rows), 80)
        self.assertIn("bundled snapshot", err)
        self.assertIn("mappings", rows[0]); self.assertIn("affected", rows[0])

    def test_vector_filter(self):
        rc, out, _ = run(["--offline", "--format", "json", "list", "--vector", "indirect-injection"])
        rows = json.loads(out)
        self.assertTrue(rows)
        self.assertTrue(all(r["vector"] == "indirect-injection" for r in rows))

    def test_vendor_and_outcome_filters(self):
        rc, out, _ = run(["--offline", "--format", "json", "list", "--vendor", "cursor", "--outcome", "code-execution"])
        rows = json.loads(out)
        self.assertTrue(rows)
        for r in rows:
            self.assertEqual(r["outcome"], "code-execution")
            self.assertTrue(any("cursor" in v.lower() for v in r["affected"]["vendors"]) or "cursor" in r["name"].lower())

    def test_mapping_tag_status_filters(self):
        rc, out, _ = run(["--offline", "--format", "json", "list", "--owasp-agentic", "ASI01"])
        rows = json.loads(out)
        self.assertTrue(rows); self.assertTrue(all("ASI01" in r["mappings"]["owasp_agentic"] for r in rows))
        rc, out, _ = run(["--offline", "--format", "json", "list", "--atlas", "AML.T0051.000"])
        self.assertTrue(json.loads(out))
        rc, out, _ = run(["--offline", "--format", "json", "list", "--tag", "chatbot", "--status", "confirmed"])
        rows = json.loads(out)
        self.assertTrue(rows); self.assertTrue(all(any("chatbot" in t for t in r["tags"]) for r in rows))
        rc, out, _ = run(["--offline", "--format", "json", "list", "--framework", "langchain"])
        self.assertTrue(json.loads(out))

    def test_since_until_and_cve(self):
        rc, out, _ = run(["--offline", "--format", "json", "list", "--since", "2025-01", "--until", "2025-12", "--cve"])
        rows = json.loads(out)
        self.assertTrue(rows)
        for r in rows:
            self.assertTrue("2025-01" <= r["date"][:7] <= "2025-12")
            self.assertTrue(r["cve"])

    def test_query_and_limit(self):
        rc, out, _ = run(["--offline", "--format", "json", "list", "--query", "MCP", "--limit", "3"])
        self.assertEqual(len(json.loads(out)), 3)

    def test_table_and_markdown_render(self):
        rc, out, _ = run(["--offline", "list", "--limit", "2"])
        self.assertIn("id", out.splitlines()[0]); self.assertIn("url", out.splitlines()[0])
        rc, out, _ = run(["--offline", "--format", "markdown", "list", "--limit", "2"])
        self.assertTrue(out.startswith("| id |")); self.assertIn("](https://", out)


class ShowStatsFieldsTests(unittest.TestCase):
    def test_show(self):
        rc, out, _ = run(["--offline", "show", "30"])
        self.assertEqual(rc, 0)
        self.assertIn("GitHub MCP server", out); self.assertIn("owasp_agentic", out); self.assertIn("source", out)
        rc, out, _ = run(["--offline", "--format", "json", "show", "030"])
        rec = json.loads(out)
        self.assertEqual(rec["id"], "030"); self.assertEqual(set(rec), set(REQUIRED))

    def test_show_missing(self):
        rc, _, err = run(["--offline", "show", "999"])
        self.assertEqual(rc, 1); self.assertIn("no incident", err)

    def test_stats(self):
        rc, out, _ = run(["--offline", "--format", "json", "stats", "--by", "outcome"])
        data = json.loads(out)
        self.assertEqual(sum(r["count"] for r in data["rows"]), data["total"])
        rc, out, _ = run(["--offline", "--format", "json", "stats", "--by", "owasp_agentic", "--vector", "indirect-injection"])
        rows = json.loads(out)["rows"]
        self.assertTrue(any(r["value"] == "ASI01" for r in rows))
        rc, out, _ = run(["--offline", "--format", "json", "stats", "--by", "vendor"])
        self.assertTrue(any(r["value"] == "OpenAI" for r in json.loads(out)["rows"]))

    def test_fields(self):
        rc, out, _ = run(["--offline", "--format", "json", "fields"])
        data = json.loads(out)
        self.assertIn("indirect-injection", data["vector"]); self.assertIn("shell/exec", data["authority"])
        self.assertIn("ASI01", data["owasp_agentic"]); self.assertIn("OpenAI", data["vendor"])


class PrecedentTests(unittest.TestCase):
    def test_ranking_prefers_full_matches(self):
        rc, out, _ = run(["--offline", "--format", "json", "precedents", "--channel-in", "repo issue/pr", "--authority", "shell/exec", "--vector", "indirect-injection"])
        data = json.loads(out)
        self.assertGreater(data["matched"], 0)
        self.assertEqual(data["precedents"][0]["score"], 8)
        scores = [p["score"] for p in data["precedents"]]
        self.assertEqual(scores, sorted(scores, reverse=True))
        self.assertIn("indirect-injection", data["controls"]); self.assertIn("owasp_agentic", data["frameworks"])
        self.assertTrue(data["precedents"][0]["url"].startswith("https://"))

    def test_design_file(self):
        with tempfile.TemporaryDirectory() as td:
            design = Path(td) / "design.json"
            design.write_text(json.dumps({"name": "support bot", "channel_in": ["support ticket", "email"], "authority": ["database"]}))
            rc, out, _ = run(["--offline", "precedents", "--design", str(design), "--limit", "5"])
            self.assertEqual(rc, 0)
            self.assertIn("support bot", out); self.assertIn("Controls that would have helped", out); self.assertIn("OWASP Agentic", out)

    def test_requires_inputs(self):
        rc, _, err = run(["--offline", "precedents"])
        self.assertEqual(rc, 2)


class SourceSelectionTests(unittest.TestCase):
    def test_explicit_data_file_accepts_schema_shape_and_legacy_shape(self):
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "d.json"
            f.write_text(json.dumps([
                {"id": "001", "date": "2026-01", "name": "x", "type": "incident", "lens": "surface", "vector": "poisoning", "channel_in": "package",
                 "authority": "none", "channel_out": "disclosure-only", "adversarial": True, "outcome": "none-demo", "cve": ["CVE-2026-0001"],
                 "sources": [{"url": "https://example.com/a", "title": "A"}], "summary": "a summary here", "mappings": {"owasp_agentic": ["ASI04"], "owasp_llm": [], "mitre_atlas": []},
                 "affected": {"vendors": ["Acme"], "products": [], "frameworks": []}, "tags": ["demo"], "status": "confirmed"},
                {"id": "2", "date": "2026-02", "name": "legacy", "vector": "poisoning", "adversarial": "yes", "cve": "-", "url": "https://example.com/b", "notes": "n", "vendors": ["Old"]},
            ]))
            rc, out, _ = run(["--data", str(f), "--format", "json", "list"])
            rows = {r["id"]: r for r in json.loads(out)}
            self.assertEqual(rows["001"]["affected"]["vendors"], ["Acme"])
            self.assertTrue(rows["2"]["adversarial"]); self.assertEqual(rows["2"]["cve"], [])
            self.assertEqual(rows["2"]["sources"][0]["url"], "https://example.com/b"); self.assertEqual(rows["2"]["summary"], "n")
            self.assertEqual(rows["2"]["affected"]["vendors"], ["Old"])

    def test_fetch_failure_falls_back_to_bundle(self):
        with tempfile.TemporaryDirectory() as td:
            env = dict(os.environ)
            os.environ["AGENT_SECURITY_INCIDENTS_URL"] = "http://127.0.0.1:9/incidents.json"
            os.environ["AGENT_SECURITY_FETCH_TIMEOUT"] = "2"
            try:
                rc, out, err = run(["--cache-dir", td, "--format", "json", "list", "--limit", "1"])
            finally:
                os.environ.clear(); os.environ.update(env)
            self.assertEqual(rc, 0); self.assertEqual(len(json.loads(out)), 1); self.assertIn("bundled snapshot", err)
            self.assertFalse((Path(td) / "agent-security-skills" / "incidents.json").exists())


if __name__ == "__main__":
    unittest.main()
