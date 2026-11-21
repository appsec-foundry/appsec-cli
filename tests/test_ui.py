import unittest

from appsec_cli.ui import Style, changes, overview, table

PLAIN = Style(False)
REPORT = {
    "tool": "security-score",
    "status": "ok",
    "summary": "Score 40/100 (Bad)",
    "target": {"kind": "repository", "path": "/repo"},
    "run": {"tool_version": "0.3.3"},
    "counts": {"critical": 0, "high": 1, "medium": 1, "low": 0, "info": 0},
    "findings": [
        {"rule": "s/a", "severity": "medium", "title": "Weak hash"},
        {
            "rule": "s/b",
            "severity": "high",
            "title": "Shell call",
            "locations": [{"kind": "file", "path": "a.py", "start_line": 3}],
            "remediation": "Use an argument list.",
        },
    ],
    "diagnostics": [
        {"level": "info", "code": "limited_evidence", "message": "Limited."}
    ],
}


class ResultView(unittest.TestCase):
    def test_frame_and_findings(self):
        text = table(REPORT, PLAIN, threshold="high", code=1)
        lines = text.splitlines()
        self.assertEqual(lines[0], "appsec-cli › security-score 0.3.3 · /repo")
        self.assertEqual(lines[2], "Score 40/100 (Bad)")
        self.assertIn("Findings · 2 · 1 high · 1 medium", text)
        self.assertLess(text.index("Shell call"), text.index("Weak hash"))
        self.assertIn(
            "   1. HIGH     Shell call\n      a.py:3\n      Fix: Use an argument list.",
            text,
        )
        self.assertIn("· Limited.", text)
        self.assertNotIn("limited_evidence", text)
        self.assertEqual(lines[-1], "✗ Threshold high reached (exit 1)")
        self.assertIn("(limited_evidence)", table(REPORT, PLAIN, code=1, verbose=True))
        passed = table(REPORT, PLAIN, threshold="critical", code=0)
        self.assertTrue(passed.endswith("✓ No finding at or above critical (exit 0)"))

    def test_filtered_and_empty_findings(self):
        shown = {**REPORT, "findings": REPORT["findings"][:1]}
        self.assertIn("Findings · showing 1 of 2", table(shown, PLAIN, code=0))
        empty = {**REPORT, "findings": [], "counts": dict.fromkeys(REPORT["counts"], 0)}
        self.assertIn("No findings.", table(empty, PLAIN, threshold="low", code=0))

    def test_incomplete_and_failed(self):
        partial = {
            **REPORT,
            "status": "partial",
            "diagnostics": [
                {"level": "warning", "code": "c", "message": "Coverage gap."}
            ],
        }
        text = table(partial, PLAIN, threshold="high", code=3)
        self.assertIn("⚠ Coverage gap.", text)
        self.assertTrue(text.endswith("⚠ Incomplete (exit 3)"))
        failed = {
            "tool": "security-score",
            "status": "failed",
            "summary": "Engine failed.",
            "diagnostics": [
                {"level": "error", "code": "x", "message": "Engine failed."}
            ],
        }
        text = table(failed, PLAIN)
        self.assertEqual(text.count("Engine failed."), 1)
        self.assertTrue(text.endswith("✗ Failed (exit 3)"))

    def test_data_views(self):
        data = {
            "git": True,
            "head": None,
            "languages": [
                {"language": "Python", "files": 31},
                {"language": "Markdown", "files": 5},
            ],
        }
        text = table({**REPORT, "data": data}, PLAIN, code=0)
        self.assertNotIn("languages", text)
        report = {k: v for k, v in REPORT.items() if k not in ("findings", "counts")}
        text = table({**report, "data": data}, PLAIN, code=0)
        self.assertIn("git: yes\nhead: -\nlanguages:\n  language  files", text)
        self.assertIn("  Python    31", text)
        self.assertTrue(text.endswith("✓ Complete (exit 0)"))
        nested = table({**report, "data": {"items": [{"a": [1], "b": 2}, {}]}}, PLAIN)
        self.assertIn("items:\n  - a:\n      - 1\n    b: 2\n  - -", nested)
        long = table({**report, "data": list(range(60))}, PLAIN, code=0)
        self.assertIn("… 20 more lines. Use --format json for the full result.", long)
        view = table({**report, "data": data}, PLAIN, lambda d: ["custom"], code=0)
        self.assertIn("\ncustom\n", view)
        self.assertNotIn("languages", view)

    def test_untrusted_text_and_colour(self):
        hostile = {
            **REPORT,
            "summary": "\x1b]0;title\x07Done",
            "findings": [],
            "counts": {},
        }
        self.assertNotIn("\x1b", table(hostile, PLAIN, code=0))
        coloured = table(REPORT, Style(True), threshold="high", code=1)
        self.assertIn("\x1b[91mHIGH", coloured)
        self.assertNotIn("\x1b]", coloured)

    def test_update_changes(self):
        before = {"version": "0.1.0", "tools": {"a": "1.0", "b": "1.0", "c": "2.0"}}
        after = {"version": "0.2.0", "tools": {"a": "1.1", "b": "1.0", "d": "0.1"}}
        text = changes({"before": before, "after": after}, PLAIN)
        self.assertEqual(
            text, "appsec-cli 0.1.0 → 0.2.0\n    a 1.0 → 1.1\n  - c\n  + d 0.1"
        )
        same = changes({"before": before, "after": before}, PLAIN)
        self.assertEqual(same, "appsec-cli 0.1.0 is up to date.")

    def test_overview_is_short(self):
        rows = [
            {
                "name": "security-score",
                "help": "Score.",
                "status": "unchecked",
                "commands": [],
            }
        ]
        lines = overview(rows, PLAIN, "0.1.0").splitlines()
        self.assertEqual(lines[:2], ["appsec-cli 0.1.0", "Application security tools"])
        self.assertIn("  security-score       Score.", lines)
