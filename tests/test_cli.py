"""CLI behaviour seen by users: help, errors and hints. Runs against an installed suite."""

import io
import json
import os
import subprocess
import sys
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
            out.startswith("appsec-cli 0.1.0\nSecurity tools from your AppSec team\n")
        )
        self.assertIn("\n    appsec-cli security-score .\n", out)
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
        self.assertIn(
            "Examples:\n  # Score the current repository\n  appsec-cli security-score .\n",
            out,
        )

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
        self.assertIn(
            "repo-profile  Repository size, languages and build manifests.", out
        )
        self.assertIn("  # Inventory the current repository\n", out)

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

    def test_score_help_shows_remote_repositories(self):
        code, out, _ = self.call("security-score", "--help")
        self.assertEqual(code, 0)
        self.assertIn("HTTPS URL of a GitHub or GitLab repository", out)
        self.assertIn("--repo REPO", out)
        self.assertIn("GIT_TOKEN", out)
        self.assertIn(
            "  appsec-cli security-score https://github.com/OWNER/REPO\n", out
        )
        self.assertIn(
            "  appsec-cli security-score https://gitlab.com/GROUP/PROJECT\n", out
        )

    def test_score_reads_a_remote_repository(self):
        from appsec_plugin_security_score import commands

        url = "https://github.com/OWNER/REPO"
        report = {
            "analysis": "security-assessment",
            "overall": {"rating": "Good"},
            "subscores": [{"score": 80}],
            "checks": [],
            "findings": [],
        }
        for args in ((url,), ("--repo", url)):
            with (
                self.subTest(args=args),
                patch.object(commands, "engine", return_value="engine"),
                patch.object(
                    commands, "invoke", return_value=(0, json.dumps(report).encode())
                ) as run,
            ):
                code, out, _ = self.call("--format", "json", "security-score", *args)
                self.assertEqual(code, 0)
                self.assertEqual(run.call_args.args[0], ["engine", url, "--json"])
                target = json.loads(out)["target"]
                self.assertEqual(target, {"kind": "repository", "url": url})

    def test_remote_repository_usage_errors(self):
        from appsec_plugin_security_score import commands

        url = "https://github.com/OWNER/REPO"
        for args, message in [
            ((url, "--repo", url), "Choose the REPO argument or --repo, not both."),
            (("http://github.com/OWNER/REPO",), "Use an HTTPS URL."),
            ((url, "--commit", "HEAD"), "need a local checkout"),
            ((url, "--staged"), "need a local checkout"),
        ]:
            with (
                self.subTest(args=args),
                patch.object(commands, "invoke") as run,
            ):
                code, out, err = self.call("security-score", *args)
                self.assertEqual((code, out), (2, ""))
                self.assertIn(message, err)
                run.assert_not_called()

    def test_git_token_reaches_only_github_and_gitlab(self):
        from appsec_plugin_security_score import commands

        report = {"analysis": "change-relevance", "relevance": "low", "checks": []}
        cases = [
            ("https://github.com/OWNER/REPO", True),
            ("https://gitlab.com/GROUP/PROJECT", True),
            ("https://gitlab.example.com/GROUP/PROJECT", False),
            ("https://github.com.example.com/OWNER/REPO", False),
            ("https://github.com@example.com/OWNER/REPO", False),
            ("https://github.com:8443/OWNER/REPO", False),
        ]
        for url, forwarded in cases:
            with (
                self.subTest(url=url),
                patch.dict(os.environ, {"GIT_TOKEN": "test-token"}),
                patch.object(commands, "engine", return_value="engine"),
                patch.object(
                    commands, "invoke", return_value=(0, json.dumps(report).encode())
                ) as run,
            ):
                code, _, _ = self.call("--format", "json", "security-score", url)
                self.assertEqual(code, 0)
                env = run.call_args.kwargs["env"]
                if forwarded:
                    self.assertIsNone(env)  # inherits GIT_TOKEN
                else:
                    self.assertNotIn("GIT_TOKEN", env)
                    self.assertEqual(env["NO_COLOR"], "1")

    def test_unreadable_remote_repository(self):
        from appsec_plugin_security_score import commands

        with (
            patch.object(commands, "engine", return_value="engine"),
            patch.object(commands, "invoke", return_value=(1, b"")),
        ):
            code, out, _ = self.call(
                "--format", "json", "security-score", "https://github.com/OWNER/REPO"
            )
        self.assertEqual(code, 3)
        diagnostic = json.loads(out)["diagnostics"][0]
        self.assertEqual(diagnostic["code"], "repository_unavailable")
        self.assertIn("GIT_TOKEN", diagnostic["message"])

    def test_disabled_tool(self):
        self.config.write_text('[plugins]\ndisabled = ["appsec-verifier"]\n')
        code, _, err = self.call("appsec-verifier", "export", "x.yaml")
        self.assertEqual(code, 2)
        self.assertIn("Error: Tool 'appsec-verifier' is disabled.", err)

    def test_start_page_loads_no_tool(self):
        script = (
            "import sys; from appsec_cli.cli import main; main([]); "
            "print(sorted(m for m in sys.modules if m.startswith('appsec_plugin_')))"
        )
        run = subprocess.run(
            [sys.executable, "-c", script], capture_output=True, text=True, check=True
        )
        self.assertIn("appsec-cli security-score .", run.stdout)
        self.assertTrue(run.stdout.endswith("\n[]\n"))

    def test_unusable_examples_leave_the_tool(self):
        broken = {"security-score": {"commands": {"missing": {}}}}
        with patch("appsec_cli.catalog.collected", return_value=broken):
            code, out, _ = self.call()
        self.assertEqual(code, 0)
        self.assertIn("  security-score ", out)
        self.assertNotIn("appsec-cli security-score .", out)

    def test_update_needs_pipx(self):
        code, _, err = self.call("update", "--yes")
        self.assertEqual(code, 2)
        self.assertIn("Error: This installation is not managed by pipx.", err)

    def test_tool_list_and_describe(self):
        code, out, _ = self.call("--format", "json", "tools", "list")
        self.assertEqual(code, 0)
        tools = {t["name"]: t for t in json.loads(out)["tools"]}
        self.assertEqual(tools["security-score"]["version"], "0.1.0")
        first = tools["security-score"]["usage"][0]["examples"][0]
        self.assertEqual(first["run"], "appsec-cli security-score .")
        code, out, _ = self.call("tools", "describe", "security-score")
        self.assertEqual(code, 0)
        self.assertIn("--commit TEXT", out)
        self.assertIn("REPO", out)
        self.assertIn("Formats: table, json, sarif", out)
        code, _, err = self.call("--format", "sarif", "tools", "list")
        self.assertEqual(code, 2)
        self.assertIn("Hint: Use --format json.", err)
