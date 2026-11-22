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
        self.assertIn(
            "Error: security-score: unrecognized arguments: --format json", err
        )
        self.assertIn(
            "Hint: --format is a global option. Put it before the tool name: "
            "appsec-cli --format",
            err,
        )

    def test_engine_errors_reach_the_user(self):
        code, out, _ = self.call(
            "--format", "json", "security-score", "/nonexistent/appsec"
        )
        self.assertEqual(code, 3)
        diagnostic = json.loads(out)["diagnostics"][0]
        self.assertEqual(diagnostic["code"], "score_failed")
        self.assertIn("does not exist", diagnostic["message"])
        code, out, err = self.call("security-score", "--repo", ".", ".")
        self.assertEqual((code, out), (2, ""))
        self.assertIn(
            "Error: security-score: Choose a positional repository or --repo", err
        )
        self.assertIn("Hint: Run 'appsec-cli security-score --help'.", err)

    def test_score_help_is_the_engine_help(self):
        code, out, _ = self.call("security-score", "--help")
        self.assertEqual(code, 0)
        self.assertIn("Usage: appsec-cli security-score [ARGS]...", out)
        self.assertIn("GIT_TOKEN", out)
        self.assertIn(
            "Arguments and options go to the engine unchanged, except --analyzer,", out
        )
        self.assertIn("usage: security-score", out)  # the engine's own help
        self.assertIn("  --repo REPO", out)
        self.assertIn(
            "  appsec-cli security-score https://github.com/OWNER/REPO\n", out
        )
        code, again, _ = self.call("security-score", ".", "--checks", "X", "-h")
        self.assertEqual((code, again), (0, out))

    def test_score_passes_its_arguments_to_the_engine(self):
        from appsec_plugin_security_score import commands

        url = "https://github.com/OWNER/REPO"
        report = {
            "analysis": "security-assessment",
            "overall": {"rating": "Good"},
            "subscores": [{"score": 80}],
            "checks": [],
            "findings": [],
        }
        for args in [
            (url,),
            ("--repo", url),
            (".", "--checks", "JS-SQL", "--timeout", "30"),
            ("--skip-checks", "PY-SQL"),
            ("--commit", "HEAD", "--details"),
            ("--checks", "X", "--", "--update"),  # after --, an argument
        ]:
            with (
                self.subTest(args=args),
                patch.object(commands, "engine", return_value="engine"),
                patch.object(
                    commands, "invoke", return_value=(0, json.dumps(report).encode())
                ) as run,
            ):
                code, _, _ = self.call("--format", "json", "security-score", *args)
                self.assertEqual(code, 0)
                self.assertEqual(run.call_args.args[0], ["engine", "--json", *args])

    def test_score_target_comes_from_the_engine(self):
        from appsec_plugin_security_score import commands

        url = "https://github.com/OWNER/REPO"
        for scope, target in [
            (
                {
                    "kind": "repository",
                    "selection": "git-url",
                    "repository": url,
                    "revision": "0123abcd",
                },
                {"kind": "repository", "url": url, "revision": "0123abcd"},
            ),
            (
                {
                    "kind": "change",
                    "selection": "git",
                    "repository": "/src/app",
                    "base": "aaa1",
                    "head": "bbb2",
                },
                {
                    "kind": "change",
                    "path": "/src/app",
                    "base": "aaa1",
                    "head": "bbb2",
                    "revision": "bbb2",
                },
            ),
        ]:
            report = {
                "analysis": "change-relevance",
                "relevance": "low",
                "checks": [],
                "scope": scope,
            }
            with (
                self.subTest(scope=scope),
                patch.object(commands, "engine", return_value="engine"),
                patch.object(
                    commands, "invoke", return_value=(0, json.dumps(report).encode())
                ),
            ):
                code, out, _ = self.call("--format", "json", "security-score", url)
                self.assertEqual(code, 0)
                self.assertEqual(json.loads(out)["target"], target)

    def test_git_token_reaches_only_github_and_gitlab(self):
        from appsec_plugin_security_score import commands

        report = {"analysis": "change-relevance", "relevance": "low", "checks": []}
        cases = [
            (("https://github.com/OWNER/REPO",), True),
            (("https://gitlab.com/GROUP/PROJECT",), True),
            (("--repo=https://github.com/OWNER/REPO",), True),
            ((".",), True),
            (("https://gitlab.example.com/GROUP/PROJECT",), False),
            (("https://github.com.example.com/OWNER/REPO",), False),
            (("https://github.com@example.com/OWNER/REPO",), False),
            (("https://github.com:8443/OWNER/REPO",), False),
            (("http://github.com/OWNER/REPO",), False),
            (
                (
                    ".",
                    "--pr",
                    "https://gitlab.example.com/GROUP/PROJECT/-/merge_requests/1",
                ),
                False,
            ),
        ]
        for args, forwarded in cases:
            with (
                self.subTest(args=args),
                patch.dict(os.environ, {"GIT_TOKEN": "test-token"}),
                patch.object(commands, "engine", return_value="engine"),
                patch.object(
                    commands, "invoke", return_value=(0, json.dumps(report).encode())
                ) as run,
            ):
                code, _, _ = self.call("--format", "json", "security-score", *args)
                self.assertEqual(code, 0)
                env = run.call_args.kwargs["env"]
                if forwarded:
                    self.assertIsNone(env)  # inherits GIT_TOKEN
                else:
                    self.assertNotIn("GIT_TOKEN", env)
                    self.assertEqual(env["NO_COLOR"], "1")

    def test_unreadable_remote_repository(self):
        from appsec_plugin_security_score import commands

        def stop(message):
            def run(argv, **kwargs):
                kwargs["stderr"].extend(message)
                return 1, b""

            return run

        for message, expected in [
            (b"", "a private repository needs GIT_TOKEN"),
            (b"Reading sources...\nRepository not found.\n", "Repository not found."),
        ]:
            with (
                self.subTest(message=message),
                patch.object(commands, "engine", return_value="engine"),
                patch.object(commands, "invoke", side_effect=stop(message)),
            ):
                code, out, _ = self.call(
                    "--format",
                    "json",
                    "security-score",
                    "https://github.com/OWNER/REPO",
                )
            self.assertEqual(code, 3)
            diagnostic = json.loads(out)["diagnostics"][0]
            self.assertEqual(diagnostic["code"], "repository_unavailable")
            self.assertIn(expected, diagnostic["message"])

    def test_score_keeps_its_reserved_engine_options(self):
        from appsec_plugin_security_score import commands

        for args in [
            ("--update",),
            ("--upd",),  # the engine accepts abbreviations
            ("--yaml",),
            ("--yam",),
            ("--quiet",),
            ("--legacy-score",),
            ("--list-checks",),
            ("--analyzer", "/bin/sh"),
            ("--anal=/bin/sh",),
            ("--token-env", "OTHER_TOKEN"),
            ("--token=OTHER_TOKEN",),
            ("--hel",),
            ("--checks", "JS-SQL", "--update"),
        ]:
            with self.subTest(args=args), patch.object(commands, "invoke") as run:
                code, out, err = self.call("security-score", ".", *args)
                self.assertEqual((code, out), (2, ""))
                self.assertIn("cannot be passed to the engine", err)
                self.assertIn("Hint: Run 'appsec-cli security-score --help'.", err)
                run.assert_not_called()

    def test_engine_usage_error_is_a_usage_error(self):
        from appsec_plugin_security_score import commands

        def refuse(argv, **kwargs):
            kwargs["stderr"].extend(
                b"usage: security-score [-h]\n"
                b"security-score: error: unrecognized arguments: --bogus\n"
            )
            return 2, b""

        with (
            patch.object(commands, "engine", return_value="engine"),
            patch.object(commands, "invoke", side_effect=refuse),
        ):
            code, out, err = self.call("security-score", ".", "--bogus")
        self.assertEqual((code, out), (2, ""))
        self.assertIn("Error: security-score: unrecognized arguments: --bogus", err)

    def test_score_details(self):
        from appsec_plugin_security_score import commands

        report = {
            "analysis": "security-assessment",
            "overall": {"rating": "Bad"},
            "subscores": [
                {
                    "title": "Identity & access",
                    "score": 59,
                    "rating": "Bad",
                    "reason": "Fast password hash",
                },
                {"title": "AI & agents", "score": None, "rating": "Not applicable"},
            ],
            "overview": {
                "languages": [{"language": "TypeScript", "files": 630}],
                "files": {"read": 1436, "lines": 287045},
                "frameworks": ["Express"],
                "routes": {"total": 110},
                "runtimes": [{"runtime": "Node.js", "version": "24"}],
                "development": {
                    "ci": [{"system": "GitHub Actions"}],
                    "security_tools": ["CodeQL"],
                },
            },
            "checks": [],
            "findings": [
                {
                    "rule": "JS-SQL",
                    "severity": "high",
                    "title": "SQL text",
                    "file": "a.ts",
                }
            ],
        }
        plain = {k: v for k, v in report.items() if k != "overview"}
        with (
            patch.object(commands, "engine", return_value="engine"),
            patch.object(
                commands, "invoke", return_value=(0, json.dumps(report).encode())
            ),
        ):
            code, out, _ = self.call(
                "--format", "json", "security-score", ".", "--details"
            )
            self.assertEqual(code, 1)
            data = json.loads(out)["data"]
            self.assertEqual(
                data["areas"][1],
                {
                    "area": "AI & agents",
                    "score": None,
                    "rating": "Not applicable",
                    "reason": None,
                },
            )
            self.assertEqual(data["overview"]["languages"], {"TypeScript": 630})
            code, out, _ = self.call("security-score", ".", "--details")
            self.assertIn("  Files           1,436 read, 287,045 lines\n", out)
            self.assertIn(
                "  Identity & access   59  Bad\n    Fast password hash\n", out
            )
            self.assertIn("  AI & agents          —  Not applicable\n", out)
            self.assertIn("Findings · 1", out)
        with (
            patch.object(commands, "engine", return_value="engine"),
            patch.object(
                commands, "invoke", return_value=(0, json.dumps(plain).encode())
            ),
        ):
            code, out, _ = self.call("--format", "json", "security-score", ".")
            data = json.loads(out)["data"]
            self.assertEqual((data["areas"], data["overview"]), (None, None))

    def test_analyzer_export_passes_its_arguments(self):
        from appsec_plugin_appsec_analyzer import commands

        args = ("--assessment", "a", "--output", "b", "--formats", "sarif")
        with (
            patch.object(commands, "engine", return_value="engine"),
            patch.object(commands, "invoke", return_value=(0, b"")) as run,
        ):
            code, out, _ = self.call(
                "--format", "json", "appsec-analyzer", "export", *args
            )
        self.assertEqual(code, 0)
        self.assertEqual(run.call_args.args[0], ["engine", "export", *args])
        self.assertEqual(json.loads(out)["summary"], "Assessment exported.")
        code, _, err = self.call("appsec-analyzer", "export", "--bogus")
        self.assertEqual(code, 2)
        self.assertIn(
            "Error: appsec-analyzer export: the following arguments are required", err
        )

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

    def test_update_hint_after_a_result_in_the_terminal(self):
        from appsec_cli import cli

        line = "appsec-cli 9.0.0 is available. Run 'appsec-cli update'."
        with (
            patch.object(cli, "interactive", return_value=True),
            patch.object(cli.updates, "hint", return_value=line) as hint,
        ):
            code, _, err = self.call()
            self.assertEqual(code, 0)
            self.assertEqual(err, "\n" + line + "\n")
            code, _, err = self.call("--format", "json")
            self.assertEqual((code, err), (0, ""))
            self.assertEqual(hint.call_count, 1)
        with patch.object(cli.updates, "hint") as hint:
            self.call()  # no terminal here
            hint.assert_not_called()

    def test_update_also_updates_injected_plugins(self):
        from appsec_cli import cli

        done = subprocess.CompletedProcess([], 0, "", "")
        failed = subprocess.CompletedProcess([], 1, "", "")
        for injected, results, warned in [
            ({}, [done], False),
            ({"appsec-plugin-team": {}}, [done, done], False),
            ({"appsec-plugin-team": {}}, [done, failed], True),
        ]:
            with (
                self.subTest(injected=injected, results=len(results)),
                patch.object(cli.shutil, "which", return_value="pipx"),
                patch.object(
                    cli.updates,
                    "pipx_metadata",
                    return_value={"injected_packages": injected},
                ),
                patch.object(cli, "installed", return_value=("0.1.0", {})),
                patch.object(cli.subprocess, "run", side_effect=results) as run,
            ):
                code, out, _ = self.call("--format", "json", "update", "--yes")
                self.assertEqual(code, 0)
                calls = [call.args[0] for call in run.call_args_list]
                self.assertEqual(calls[0], ["pipx", "upgrade", "appsec-cli"])
                if injected:
                    self.assertEqual(
                        calls[1],
                        ["pipx", "upgrade", "--include-injected", "appsec-cli"],
                    )
                self.assertEqual("warnings" in json.loads(out), warned)

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
        self.assertIn("Arguments go to the engine unchanged, except --analyzer", out)
        self.assertIn("Formats: table, json, sarif", out)
        code, out, _ = self.call(
            "--format", "json", "tools", "describe", "security-score"
        )
        definition = json.loads(out)["definitions"][0]
        self.assertEqual(definition["parameters"], [])
        self.assertIn("--update", definition["forwards_except"])
        code, _, err = self.call("--format", "sarif", "tools", "list")
        self.assertEqual(code, 2)
        self.assertIn("Hint: Use --format json.", err)
