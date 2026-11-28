"""CLI behaviour seen by users: help, errors and hints. Runs against an installed suite.

The tools here are the test plugins of plugin_fixture, not the shipped tools;
each shipped tool tests itself in tools/NAME/tests.
"""

import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import replace
from importlib.metadata import metadata, version
from pathlib import Path
from unittest.mock import patch

import plugin_fixture
from appsec_cli import Passthrough, ToolError, catalog
from appsec_cli import cli as cli_module
from appsec_cli.cli import main


class Cli(unittest.TestCase):
    def setUp(self):
        plugin_fixture.install()
        home = tempfile.TemporaryDirectory()
        self.addCleanup(home.cleanup)
        self.config = Path(home.name, "appsec-cli/config.toml")
        self.config.parent.mkdir()
        self.config.write_text(plugin_fixture.CONFIG)
        env = patch.dict(os.environ, {"XDG_CONFIG_HOME": home.name, "NO_COLOR": "1"})
        env.start()
        self.addCleanup(env.stop)
        for target, value in [
            ("appsec_cli.catalog.collected", lambda: plugin_fixture.USAGE),
            ("appsec_cli.cli.engine", plugin_fixture.engine(cli_module.engine)),
        ]:
            patcher = patch(target, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def call(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = main(list(args))
        return code, out.getvalue(), err.getvalue()

    def test_start_page_and_help(self):
        code, out, _ = self.call()
        self.assertEqual(code, 0)
        suite = metadata("appsec-cli")["Summary"]
        self.assertTrue(
            out.startswith(f"appsec-cli {version('appsec-cli')}\n{suite}\n")
        )
        self.assertIn("\n    appsec-cli fixture .\n", out)
        self.assertNotIn("tools new", out)
        code, out, _ = self.call("--help")
        self.assertEqual(code, 0)
        self.assertIn("Global options (before the tool name)", out)
        self.assertIn("--fail-on", out)

    def test_tool_help_has_no_escapes(self):
        code, out, _ = self.call("fixture", "--help")
        self.assertEqual(code, 0)
        self.assertNotIn("\\[", out)
        self.assertIn(
            "Examples:\n  # Scan the current repository\n  appsec-cli fixture .\n", out
        )

    def test_unknown_names_suggest_the_closest(self):
        code, _, err = self.call("fixtre", ".")
        self.assertEqual(code, 2)
        self.assertEqual(
            err, "Error: Unknown tool 'fixtre'.\nHint: Did you mean 'fixture'?\n"
        )
        code, _, err = self.call("fixture-group", "exprt")
        self.assertEqual(code, 2)
        self.assertIn("Hint: Did you mean 'export'?", err)
        code, out, _ = self.call("fixture-group")
        self.assertEqual(code, 0)
        self.assertIn("export  Export a saved report.", out)
        self.assertIn("  # Export it\n", out)

    def test_global_option_after_tool(self):
        code, _, err = self.call("fixture", ".", "--format", "json")
        self.assertEqual(code, 2)
        self.assertIn(
            "Error: fixture-engine: unrecognized arguments: --format json", err
        )
        self.assertIn(
            "Hint: --format is a global option. Put it before the tool name: "
            "appsec-cli --format",
            err,
        )

    def test_no_color_applies_to_the_help(self):
        with patch.dict(os.environ, {"FORCE_COLOR": "1"}):
            del os.environ["NO_COLOR"]
            _, coloured, _ = self.call("--help")
            code, out, _ = self.call("--no-color", "--help")
        # click drops the escape codes off a terminal; the logo shows the choice.
        self.assertIn("╭", coloured)
        self.assertEqual(code, 0)
        self.assertTrue(out.startswith("appsec-cli "))
        self.assertNotIn("╭", out)

    def test_debug_shows_the_traceback(self):
        def broken(*args):
            try:
                raise ValueError("original cause")
            except ValueError:
                raise ToolError("tool_failed", "The tool failed.") from None

        with patch("appsec_cli.cli.finalize", side_effect=broken):
            code, out, err = self.call("--format", "json", "fixture", ".")
            self.assertEqual(code, 3)
            self.assertNotIn("Traceback", err)
            self.assertNotIn("original cause", out + err)
            code, out, err = self.call("--debug", "--format", "json", "fixture", ".")
        self.assertEqual(code, 3)
        self.assertEqual(json.loads(out)["diagnostics"][0]["code"], "tool_failed")
        self.assertIn("Traceback", err)
        self.assertIn("ValueError: original cause", err)
        self.assertNotIn("original cause", out)

    def test_global_option_after_a_terminal_wrapper(self):
        load = catalog.Tool.load

        def terminal(tool, subcommand):
            spec = load(tool, subcommand)
            return replace(
                spec, passthrough=lambda ctx: Passthrough(["engine", *ctx.args])
            )

        with (
            patch.object(catalog.Tool, "load", terminal),
            patch("appsec_cli.cli.attached", return_value=2) as attached,
        ):
            code, _, err = self.call("fixture", ".", "--format", "json")
            self.assertEqual(code, 2)
            self.assertEqual(
                attached.call_args.args[0], ["engine", ".", "--format", "json"]
            )
            self.assertIn(
                "Hint: --format is a global option. Put it before the tool name: "
                "appsec-cli --format … fixture …",
                err,
            )
            attached.return_value = 1
            code, _, err = self.call("fixture", ".", "--format", "json")
        self.assertEqual((code, err), (1, ""))

    def test_terminal_wrapper_sets_the_time_limit(self):
        load = catalog.Tool.load
        calls = [
            Passthrough(["engine"]),
            Passthrough(["engine"], timeout=900),
            Passthrough(["engine"], timeout=None),
        ]

        def terminal(tool, subcommand):
            return replace(load(tool, subcommand), passthrough=lambda ctx: calls.pop(0))

        with (
            patch.object(catalog.Tool, "load", terminal),
            patch("appsec_cli.cli.attached", return_value=0) as attached,
        ):
            self.call("fixture", ".")
            self.assertEqual(attached.call_args.kwargs["timeout"], 120)
            self.call("fixture", ".")
            self.assertEqual(attached.call_args.kwargs["timeout"], 900)
            self.call("fixture", ".")
            self.assertIsNone(attached.call_args.kwargs["timeout"])

    def test_engine_errors_reach_the_user(self):
        code, out, _ = self.call("--format", "json", "fixture", ".", "--fail")
        self.assertEqual(code, 3)
        diagnostic = json.loads(out)["diagnostics"][0]
        self.assertEqual(diagnostic["code"], "scan_failed")
        self.assertIn("does not exist", diagnostic["message"])
        code, out, err = self.call("fixture", ".", "--bogus")
        self.assertEqual((code, out), (2, ""))
        self.assertIn("Error: fixture-engine: unrecognized arguments: --bogus", err)
        self.assertIn("Hint: Run 'appsec-cli fixture --help'.", err)
        code, _, err = self.call("fixture-group", "export")
        self.assertEqual(code, 2)
        self.assertIn("Missing argument 'REPORT'", err)

    def test_findings_set_the_exit_code(self):
        code, out, _ = self.call("--format", "json", "fixture", ".", "--finding")
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(out)["counts"]["high"], 1)
        code, out, _ = self.call("fixture", ".", "--finding")
        self.assertEqual(code, 1)
        self.assertIn("Findings · 1", out)
        code, _, _ = self.call("--fail-on", "never", "fixture", ".", "--finding")
        self.assertEqual(code, 0)

    def test_json_names_the_threshold_behind_exit_1(self):
        def run(*options, engine=()):
            code, out, _ = self.call(
                "--format", "json", *options, "fixture", ".", "--finding", *engine
            )
            return code, json.loads(out).get("diagnostics", [])

        reached = {
            "level": "info",
            "code": "threshold_reached",
            "message": "Threshold high reached by 1 finding (exit 1).",
        }
        # Filters shorten the list, not the count behind the exit code.
        self.assertEqual(run("--fail-on", "high", "--limit", "0"), (1, [reached]))
        self.assertEqual(run("--fail-on", "critical"), (0, []))
        self.assertEqual(run("--fail-on", "never"), (0, []))
        code, diagnostics = run("--fail-on", "high", engine=["--partial"])
        self.assertEqual(code, 3)
        self.assertNotIn("threshold_reached", [d["code"] for d in diagnostics])
        # The terminal says it once, in the outcome line.
        code, out, _ = self.call("--fail-on", "high", "fixture", ".", "--finding")
        self.assertEqual(code, 1)
        self.assertNotIn("reached by", out)
        self.assertIn("Threshold high reached (exit 1)", out)

    def test_wrapper_help_is_the_engine_help(self):
        code, out, _ = self.call("fixture", "--help")
        self.assertEqual(code, 0)
        self.assertIn("Usage: appsec-cli fixture [ARGS]...", out)
        self.assertIn("Scan with the fixture engine.", out)
        self.assertIn(
            "Arguments and options go to the engine unchanged, except --analyzer,", out
        )
        self.assertIn(
            "With --format json before the tool name, appsec-cli returns its common "
            "result; output options of the engine print the engine's own format.",
            " ".join(out.split()),
        )
        self.assertIn("usage: fixture-engine", out)  # the engine's own help
        self.assertIn("  --checks CHECKS", out)
        self.assertIn("  appsec-cli fixture .\n", out)
        code, again, _ = self.call("fixture", ".", "--checks", "X", "-h")
        self.assertEqual((code, again), (0, out))

    def test_wrapper_passes_its_arguments_to_the_engine(self):
        for args in [
            (".",),
            (".", "--checks", "JS-SQL"),
            ("--checks=JS-SQL", "a", "b"),
            ("--checks", "X", "--", "--update"),  # after --, an argument
        ]:
            with self.subTest(args=args):
                code, out, _ = self.call("--format", "json", "fixture", *args)
                self.assertEqual(code, 0)
                self.assertEqual(json.loads(out)["data"]["args"], list(args))

    def test_wrapper_keeps_its_reserved_engine_options(self):
        from appsec_plugin_fixture import scan

        self.assertEqual(scan.forward_except, ("--update", "--analyzer", "--token-env"))
        for args in [
            ("--update",),
            ("--upd",),  # argparse engines accept abbreviations
            ("--analyzer", "/bin/sh"),
            ("--anal=/bin/sh",),
            ("--token-env", "OTHER_TOKEN"),
            ("--token=OTHER_TOKEN",),
            ("--hel",),
            ("--checks", "JS-SQL", "--update"),
        ]:
            with (
                self.subTest(args=args),
                patch("appsec_plugin_fixture.invoke") as run,
            ):
                code, out, err = self.call("fixture", ".", *args)
                self.assertEqual((code, out), (2, ""))
                self.assertIn("cannot be passed to the engine", err)
                self.assertIn("Hint: Run 'appsec-cli fixture --help'.", err)
                run.assert_not_called()

    def test_disabled_tool(self):
        self.config.write_text(plugin_fixture.CONFIG + 'disabled = ["fixture"]\n')
        code, _, err = self.call("fixture", ".")
        self.assertEqual(code, 2)
        self.assertIn("Error: Tool 'fixture' is disabled.", err)
        # The suite also ships tools that stay off, such as requirement-harvester.
        hint = (
            r"(?m)^\d+ disabled tools? not shown\. See 'appsec-cli tools list --all'\.$"
        )
        _, out, _ = self.call("tools", "list")
        self.assertNotIn("  fixture ", out)
        self.assertRegex(out, hint)
        _, out, _ = self.call("tools", "list", "--all")
        self.assertIn("[disabled]", out)
        self.assertNotIn("not shown", out)

    def test_start_page_loads_no_tool(self):
        script = (
            "import sys; from unittest import mock; import plugin_fixture\n"
            "from appsec_cli.cli import main\n"
            "with mock.patch('appsec_cli.catalog.collected', lambda: plugin_fixture.USAGE):\n"
            "    main([])\n"
            "print(sorted(m for m in sys.modules if m.startswith('appsec_plugin_')))"
        )
        path = os.pathsep.join(
            [str(Path(__file__).parent), str(plugin_fixture.install())]
        )
        run = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True,
            text=True,
            check=True,
            env={**os.environ, "PYTHONPATH": path},
        )
        self.assertIn("appsec-cli fixture .", run.stdout)
        self.assertTrue(run.stdout.endswith("\n[]\n"))

    def test_unusable_examples_leave_the_tool(self):
        broken = {"fixture": {"commands": {"missing": {}}}}
        with patch("appsec_cli.catalog.collected", return_value=broken):
            code, out, _ = self.call()
        self.assertEqual(code, 0)
        self.assertIn("  fixture ", out)
        self.assertNotIn("appsec-cli fixture .", out)

    def test_a_run_in_the_terminal_names_the_tool_first(self):
        from appsec_cli import cli

        load = catalog.Tool.load
        seen = []

        def terminal(tool, subcommand):
            return replace(
                load(tool, subcommand), passthrough=lambda ctx: Passthrough(["engine"])
            )

        def engine(*args, **kwargs):
            seen.append(sys.stderr.getvalue())
            return 0

        with (
            patch.object(cli, "interactive", return_value=True),
            patch.object(cli.updates, "hint", return_value=None),
        ):
            code, _, err = self.call("fixture", ".")
            self.assertEqual((code, err), (0, "Starting fixture 0.1.0 …\n"))
            code, _, err = self.call("fixture-group", "export", "report")
            self.assertEqual(
                (code, err), (0, "Starting fixture-group export 0.1.0 …\n")
            )
            # Neither help nor a refused option starts the tool.
            self.assertEqual(self.call("-v", "fixture", "--help")[2], "")
            code, _, err = self.call("fixture", "--update")
            self.assertEqual(code, 2)
            self.assertTrue(err.startswith("Error: "))
            # A wrapper's engine answers after the line.
            with (
                patch.object(catalog.Tool, "load", terminal),
                patch("appsec_cli.cli.attached", side_effect=engine),
            ):
                self.assertEqual(self.call("fixture", ".")[0], 0)
            self.assertEqual(seen, ["Starting fixture 0.1.0 …\n"])
        # Outside a terminal only -v shows it.
        self.assertEqual(self.call("--format", "json", "fixture", ".")[2], "")
        code, _, err = self.call("-v", "--format", "json", "fixture", ".")
        self.assertEqual((code, err), (0, "Starting fixture 0.1.0 …\n"))

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
                for call in run.call_args_list:
                    self.assertIs(call.kwargs.get("stdin"), subprocess.DEVNULL)
                if injected:
                    self.assertEqual(
                        calls[1],
                        ["pipx", "upgrade", "--include-injected", "appsec-cli"],
                    )
                self.assertEqual("warnings" in json.loads(out), warned)

    def test_update_says_what_it_does_in_the_terminal(self):
        from appsec_cli import cli

        done = subprocess.CompletedProcess([], 0, "", "")
        with (
            patch.object(cli.shutil, "which", return_value="pipx"),
            patch.object(cli.updates, "pipx_metadata", return_value={}),
            patch.object(cli, "installed", return_value=("0.1.0", {})),
            patch.object(cli.subprocess, "run", return_value=done),
        ):
            code, out, err = self.call("update", "--yes")
            self.assertEqual(code, 0)
            self.assertEqual(err, "Updating appsec-cli with pipx …\n")
            self.assertTrue(out.startswith("No release newer than appsec-cli 0.1.0"))
            code, _, err = self.call("--format", "json", "update", "--yes")
            self.assertEqual((code, err), (0, ""))

    def test_update_reads_the_versions_outside_the_project(self):
        # A project file this version cannot read must not stop the update.
        project = tempfile.TemporaryDirectory()
        self.addCleanup(project.cleanup)
        Path(project.name, ".appsec-cli.toml").write_text("new_setting = true\n")
        here = os.getcwd()
        os.chdir(project.name)
        self.addCleanup(os.chdir, here)
        suite, _ = cli_module.installed()
        self.assertEqual(suite, version("appsec-cli"))

    def test_update_names_a_missing_login(self):
        from appsec_cli import cli

        asked = subprocess.CompletedProcess(
            [], 1, "", "User for pypi.example.com: Traceback\nEOFError\n"
        )
        with (
            patch.object(cli.shutil, "which", return_value="pipx"),
            patch.object(cli.updates, "pipx_metadata", return_value={}),
            patch.object(cli, "installed", return_value=("0.1.0", {})),
            patch.object(cli.subprocess, "run", return_value=asked),
        ):
            code, out, err = self.call("--format", "json", "update", "--yes")
        self.assertEqual(code, 3)
        self.assertIn("asks for a login", json.loads(out)["summary"])
        self.assertNotIn("Traceback", err)

    def test_update_needs_pipx(self):
        code, _, err = self.call("update", "--yes")
        self.assertEqual(code, 2)
        self.assertIn("Error: This installation is not managed by pipx.", err)

    def test_tool_list_and_describe(self):
        code, out, _ = self.call("--format", "json", "tools", "list")
        self.assertEqual(code, 0)
        tools = {t["name"]: t for t in json.loads(out)["tools"]}
        self.assertEqual(tools["fixture"]["version"], "0.1.0")
        first = tools["fixture"]["usage"][0]["examples"][0]
        self.assertEqual(first["run"], "appsec-cli fixture .")
        code, out, _ = self.call("tools", "describe", "fixture")
        self.assertEqual(code, 0)
        self.assertIn("Arguments go to the engine unchanged, except --analyzer", out)
        self.assertIn("Formats: table, json, sarif", out)
        code, out, _ = self.call("--format", "json", "tools", "describe", "fixture")
        definition = json.loads(out)["definitions"][0]
        self.assertEqual(definition["parameters"], [])
        self.assertIn("--update", definition["forwards_except"])
        code, _, err = self.call("--format", "sarif", "tools", "list")
        self.assertEqual(code, 2)
        self.assertIn("Hint: Use --format json.", err)

    def test_commands_follow_the_manifest(self):
        """The manifest orders a tool's commands; commands it leaves out follow."""
        group = plugin_fixture.USAGE["fixture-group"]["commands"]
        for commands in [
            {"show": group["show"], "export": group["export"]},
            {"show": group["show"]},
        ]:
            tables = {**plugin_fixture.USAGE, "fixture-group": {"commands": commands}}
            with self.subTest(list(commands)), patch(
                "appsec_cli.catalog.collected", return_value=tables
            ):
                _, start, _ = self.call()
                _, out, _ = self.call("fixture-group", "--help")
                _, described, _ = self.call(
                    "--format", "json", "tools", "describe", "fixture-group"
                )
                listed = out.split("Commands:\n")[1]
                self.assertLess(listed.index("show"), listed.index("export"))
                self.assertLess(
                    start.index("fixture-group show"),
                    start.index("fixture-group export"),
                )
                self.assertEqual(
                    [d["command"] for d in json.loads(described)["definitions"]],
                    ["fixture-group show", "fixture-group export"],
                )

    def test_a_named_engine_gives_the_version(self):
        fixture = {**plugin_fixture.USAGE["fixture"], "engine": "click"}
        named = {**plugin_fixture.USAGE, "fixture": fixture}
        with patch("appsec_cli.catalog.collected", return_value=named):
            _, out, _ = self.call("--format", "json", "tools", "list")
            _, run, _ = self.call("--format", "json", "fixture", ".")
            _, versions, _ = self.call("--version")
        tools = {t["name"]: t for t in json.loads(out)["tools"]}
        self.assertEqual(tools["fixture"]["version"], version("click"))
        self.assertEqual(tools["fixture"]["plugin_version"], "0.1.0")
        self.assertEqual(tools["fixture-group"]["version"], "0.1.0")
        self.assertEqual(json.loads(run)["run"]["tool_version"], version("click"))
        self.assertEqual(json.loads(run)["run"]["plugin_version"], "0.1.0")
        lines = [line.split() for line in versions.splitlines()]
        self.assertIn(["fixture", version("click")], lines)
        fixture["engine"] = "appsec-no-such-engine"
        with patch("appsec_cli.catalog.collected", return_value=named):
            _, out, _ = self.call("--format", "json", "tools", "list")
            code, run, _ = self.call("fixture", ".")
        tools = {t["name"]: t for t in json.loads(out)["tools"]}
        self.assertEqual(tools["fixture"]["status"], "missing")
        self.assertEqual(tools["fixture"]["version"], "0.1.0")
        self.assertEqual(code, 3)
        self.assertIn("fixture is missing.", run)
