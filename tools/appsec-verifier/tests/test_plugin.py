"""appsec-verifier adapter: which fields of a verification report it exports.

Run with the Python of an installed suite:
python -m unittest discover -s tools/appsec-verifier/tests
"""

import json
import tempfile
import unittest
from pathlib import Path

from appsec_cli import ToolError
from appsec_plugin_appsec_verifier.commands import export


class Verifier(unittest.TestCase):
    def test_report_projection(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, "verification.yaml")
            good = """meta: {schema_version: 1, generated: "2026-01-01", verifier_version: x, source_assessment: a, target: {}, scope: {file: null}, authorization: {confirmed: true, mode: ci-flag}, limits: {}}
results: [{result_id: VF-001, eligibility: {status: dynamic}, finding_ref: {id: F-1, match_key: a.py}, verdict: confirmed, unused_internal_field: private}]
"""
            path.write_text(good)
            data = export.handler(path).data
            self.assertEqual(data["annotations"][0]["verdict"], "confirmed")
            self.assertNotIn("private", json.dumps(data))
            path.write_text(good.replace("verdict: confirmed", "verdict: shown-without-exploit"))
            data = export.handler(path).data
            self.assertEqual(data["annotations"][0]["verdict"], "shown-without-exploit")
            for invalid in [
                good.replace("version: 1", "version: 2"),
                good.replace("verdict: confirmed", "verdict: approved"),
                "x: &a test\ny: *a",
                "!!python/object:Test {}",
                "results: [{}]",
            ]:
                path.write_text(invalid)
                with self.assertRaises(ToolError):
                    export.handler(path)


if __name__ == "__main__":
    unittest.main()
