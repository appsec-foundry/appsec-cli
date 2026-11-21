"""CLI behaviour seen by users: help, errors and hints. Runs against an installed suite."""

import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from appsec_cli.cli import main


class Cli(unittest.TestCase):
    def setUp(self):
        home = tempfile.TemporaryDirectory()
        self.addCleanup(home.cleanup)
        self.config = Path(home.name, "appsec-cli/config.toml")
        self.config.parent.mkdir()
        env = patch.dict(os.environ, {"XDG_CONFIG_HOME": home.name, "NO_COLOR": "1"})
        env.start()
        self.addCleanup(env.stop)

    def call(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = main(list(args))
        return code, out.getvalue(), err.getvalue()

    def test_start_page_and_help(self):
        code, out, _ = self.call()
        self.assertEqual(code, 0)
        self.assertTrue(
            out.startswith("appsec-cli 0.1.0\nApplication security tools\n")
        )
        self.assertNotIn("tools new", out)
        code, out, _ = self.call("--help")
        self.assertEqual(code, 0)
        self.assertIn("Global options (before the tool name)", out)
        self.assertIn("--fail-on", out)

    def test_tool_help_has_no_escapes(self):
        code, out, _ = self.call("security-score", "--help")
        self.assertEqual(code, 0)
        self.assertIn("[default: .]", out)
        self.assertNotIn("\\[", out)

    def test_unknown_names_suggest_the_closest(self):
        code, _, err = self.call("securityscore", ".")
        self.assertEqual(code, 2)
        self.assertEqual(
            err,
            "Error: Unknown tool 'securityscore'.\nHint: Did you mean 'security-score'?\n",
        )
        code, _, err = self.call("appsec-analyzer", "exprt")
        self.assertEqual(code, 2)
        self.assertIn("Hint: Did you mean 'export'?", err)
        code, out, _ = self.call("appsec-analyzer")
        self.assertEqual(code, 0)
        self.assertIn("repo-profile", out)

    def test_global_option_after_tool(self):
        code, _, err = self.call("security-score", ".", "--format", "json")
        self.assertEqual(code, 2)
        self.assertIn("Error: --format is a global option.", err)
        self.assertIn("Hint: Put it before the tool name: appsec-cli --format", err)

    def test_missing_path_is_a_usage_error(self):
        code, out, err = self.call("security-score", "/nonexistent/appsec")
        self.assertEqual((code, out), (2, ""))
        self.assertIn("does not exist", err)
        self.assertIn("Hint: Run 'appsec-cli security-score --help'.", err)

    def test_disabled_tool(self):
        self.config.write_text('[plugins]\ndisabled = ["appsec-verifier"]\n')
        code, _, err = self.call("appsec-verifier", "export", "x.yaml")
        self.assertEqual(code, 2)
        self.assertIn("Error: Tool 'appsec-verifier' is disabled.", err)

    def test_update_needs_pipx(self):
        code, _, err = self.call("update", "--yes")
        self.assertEqual(code, 2)
        self.assertIn("Error: This installation is not managed by pipx.", err)

    def test_tool_list_and_describe(self):
        code, out, _ = self.call("--format", "json", "tools", "list")
        self.assertEqual(code, 0)
        tools = {t["name"]: t for t in json.loads(out)["tools"]}
        self.assertEqual(tools["security-score"]["version"], "0.1.0")
        code, out, _ = self.call("tools", "describe", "security-score")
        self.assertEqual(code, 0)
        self.assertIn("--commit TEXT", out)
        self.assertIn("REPO", out)
        self.assertIn("Formats: table, json, sarif", out)
        code, _, err = self.call("--format", "sarif", "tools", "list")
        self.assertEqual(code, 2)
        self.assertIn("Hint: Use --format json.", err)
