"""Scaling guard for audit_agent_config.py: one finding per risky allow rule must not cost a pass over the file.

Before 0.6.0 every finding counted newlines from the start of the file, so a settings file with thousands of risky
rules took seconds (24,000 findings in a 900 KB file: 6.8 s). The test compares two sizes in one process: from
2,000 to 16,000 rules linear work grows about eight times, the old lookup about twenty-four times.
"""
from __future__ import annotations

import json
import sys
import tempfile
import time
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import audit_agent_config as audit  # noqa: E402


def timed_audit(n: int) -> tuple[float, int, list]:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / ".claude").mkdir()
        rules = [f"Bash(rm -rf /tmp/build{i})" for i in range(n)]
        (root / ".claude" / "settings.json").write_text(json.dumps({"permissions": {"allow": rules}}, indent=1), encoding="utf-8")
        auditor = audit.Auditor(root)
        start = time.perf_counter()
        auditor.run()
        return time.perf_counter() - start, len(auditor.findings), auditor.findings


class ScalingTest(unittest.TestCase):
    def test_many_risky_rules_scale_linearly(self):
        small, n_small, _ = min((timed_audit(2000) for _ in range(2)), key=lambda r: r[0])
        large, n_large, findings = min((timed_audit(16000) for _ in range(2)), key=lambda r: r[0])
        self.assertGreaterEqual(n_large, 16000)
        self.assertGreater(n_large, n_small)
        # line numbers stay exact: rule i sits on line i + 4 of the indented JSON
        by_rule = {f.evidence: f.line for f in findings if f.evidence.startswith("Bash(rm -rf /tmp/build")}
        self.assertEqual(by_rule.get("Bash(rm -rf /tmp/build10)"), 14)
        self.assertEqual(by_rule.get("Bash(rm -rf /tmp/build1)"), 5)
        self.assertLess(large, max(small, 0.01) * 14, f"2,000 rules {small:.3f}s, 16,000 rules {large:.3f}s")


if __name__ == "__main__":
    unittest.main()
