import unittest

from appsec_plugin_template import run


class PluginContract(unittest.TestCase):
    def test_finding_and_data(self):
        result = run.handler("TODO: check")
        self.assertEqual(result.status, "ok")
        self.assertEqual(result.data, {"characters": 11})
        self.assertEqual(result.findings[0].severity, "info")
        self.assertEqual(run.handler("done").findings, [])
