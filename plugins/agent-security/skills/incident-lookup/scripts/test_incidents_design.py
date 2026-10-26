"""Tests for `precedents --design`: design files in JSON, flat text and scan_agent_stack.py --json form."""
from __future__ import annotations

import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import incidents  # noqa: E402


def precedents(design_text: str) -> tuple[int, dict | None, str]:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "design.json"
        path.write_text(design_text, encoding="utf-8")
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            try:
                rc = incidents.main(["--offline", "--format", "json", "precedents", "--design", str(path)])
            except SystemExit as exc:
                rc = exc.code
        return rc, (json.loads(out.getvalue()) if out.getvalue().strip() else None), err.getvalue()


class DesignFileTest(unittest.TestCase):
    def test_scan_output_is_a_design(self):
        scan = {"detections": {"hits": {"inputs": {"email": ["crew.py"]}, "authorities": {"send-message": ["crew.py"]}}},
                "model": {"system": {"name": "newsletter"}}}
        rc, data, _ = precedents(json.dumps(scan))
        self.assertEqual(rc, 0)
        self.assertEqual(data["design"], "newsletter")
        self.assertEqual(data["inputs"]["channel_in"], ["email"])
        self.assertEqual(data["inputs"]["authority"], ["send-message"])
        self.assertGreater(data["matched"], 0)
        self.assertTrue(all("email" in p["why"] or "send-message" in p["why"] for p in data["precedents"]))

    def test_scan_with_nothing_detected_asks_for_inputs(self):
        rc, data, err = precedents(json.dumps({"detections": {"hits": {}}}))
        self.assertEqual(rc, 2)
        self.assertIn("give at least one", err)

    def test_flat_text_design_still_works(self):
        rc, data, _ = precedents("name: helpdesk\nchannel_in: support ticket\nauthority: send-message, shell/exec\n")
        self.assertEqual(rc, 0)
        self.assertEqual(data["design"], "helpdesk")
        self.assertEqual(data["inputs"]["authority"], ["send-message", "shell/exec"])

    def test_wrong_shapes_exit_2_or_are_ignored(self):
        self.assertEqual(precedents("[1, 2]")[0], 2)
        rc, data, _ = precedents(json.dumps({"channel_in": "email", "authority": [1, "send-message"], "name": 5}))
        self.assertEqual(rc, 0)
        self.assertEqual(data["inputs"], {"channel_in": ["email"], "authority": ["send-message"], "vector": [], "channel_out": []})
        self.assertEqual(data["design"], "the design")


if __name__ == "__main__":
    unittest.main()
