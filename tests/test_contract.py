"""Run against an installed suite with python -m unittest discover -s tests."""

import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import jsonschema
from appsec_cli import Finding, Result, ToolError, command
from appsec_cli.config import Settings, settings, shown
from appsec_cli.external import attached, invoke
from appsec_cli.output import finalize, sarif
from appsec_cli.sdk import Envelope


class Contracts(unittest.TestCase):
    def test_data_only_and_rules(self):
        @command(data=int)
        def number():
            return Result(summary="Score", data=45)

        report, code = finalize(number.handler(), "score", number, {}, "low", "high", 0)
        jsonschema.validate(report, Envelope.model_json_schema())
        self.assertEqual(code, 0)
        self.assertNotIn("findings", report)
        self.assertEqual(report["data"], 45)

        @command(findings=True)
        def scan():
            return Result(
                summary="Completed",
                findings=[
                    Finding(rule="test/x", title=s, severity=s)
                    for s in ("info", "high")
                ],
            )

        result = scan.handler()
        report, code = finalize(result, "test", scan, {}, "high", "info", 1)
        self.assertEqual(code, 1)
        self.assertEqual(report["counts"]["high"], 1)
        run = sarif(report, result.findings)["runs"][0]
        self.assertNotIn("version", run["tool"]["driver"])
        versioned = sarif({**report, "run": {"tool_version": "1.2.0"}})
        self.assertEqual(versioned["runs"][0]["tool"]["driver"]["version"], "1.2.0")
        self.assertEqual(run["results"][0]["level"], "error")  # limit 1 keeps high
        self.assertEqual(
            run["tool"]["driver"]["rules"][0]["properties"]["security-severity"], "8.0"
        )

    def test_limit_keeps_the_most_severe_findings(self):
        @command(findings=True)
        def scan():
            return Result(
                summary="Completed",
                findings=[
                    Finding(rule="test/x", title=f"{s} {n}", severity=s)
                    for n, s in enumerate(("low", "high", "medium", "high"))
                ],
            )

        report, _ = finalize(scan.handler(), "test", scan, {}, "high", "info", 2)
        self.assertEqual([f["title"] for f in report["findings"]], ["high 1", "high 3"])
        report, _ = finalize(scan.handler(), "test", scan, {}, "high", "info", None)
        self.assertEqual(
            [f["title"] for f in report["findings"]],
            ["high 1", "high 3", "medium 2", "low 0"],
        )
        self.assertEqual(report["counts"]["high"], 2)

    def test_update_hint(self):
        from importlib.metadata import version

        from appsec_cli import updates

        newer = "appsec-cli 9.0.0 is available. Run 'appsec-cli update'."
        with (
            tempfile.TemporaryDirectory() as tmp,
            patch.dict(os.environ, {"XDG_CACHE_HOME": tmp}),
            patch.object(updates, "pipx_metadata", return_value={}),
            patch.object(updates, "latest", return_value="9.0.0") as look,
        ):
            self.assertEqual(updates.hint(now=1000.0), newer)
            self.assertIsNone(updates.hint(now=1000.0 + 3600))  # once a day
            self.assertEqual(look.call_count, 1)
            self.assertEqual(updates.hint(now=1000.0 + updates.DAY), newer)
            look.return_value = version("appsec-cli")
            self.assertIsNone(updates.hint(now=1000.0 + 2 * updates.DAY))
            look.return_value = None  # index unreachable or not configured
            self.assertIsNone(updates.hint(now=1000.0 + 3 * updates.DAY))
            with patch.dict(os.environ, {"APPSEC_CLI_NO_UPDATE_CHECK": "1"}):
                self.assertIsNone(updates.hint(now=1000.0 + 4 * updates.DAY))
            self.assertEqual(look.call_count, 4)
        with (
            patch.object(updates, "pipx_metadata", return_value=None),
            patch.object(updates, "latest") as look,
        ):
            self.assertIsNone(updates.hint())
            look.assert_not_called()

    def test_update_hint_asks_only_a_team_index(self):
        from appsec_cli import updates

        self.assertTrue(
            updates.team_index("global.index-url='https://pkgs.example.com/simple'")
        )
        self.assertTrue(updates.team_index(":env:.no-index='1'"))
        self.assertFalse(
            updates.team_index("global.index-url='https://pypi.org/simple'")
        )
        self.assertFalse(updates.team_index("global.timeout='5'"))
        listing = "appsec-cli (0.2.0)\nAvailable versions: 0.2.0, 0.1.0\n"
        for config, expected, asked in [
            ("global.index-url='https://pkgs.example.com/simple'\n", "0.2.0", True),
            ("", None, False),
            (None, None, False),
        ]:
            calls = []

            def pip(args, deadline):
                calls.append(args[1])
                return config if args[1] == "config" else listing

            with self.subTest(config=config), patch.object(updates, "run_pip", pip):
                self.assertEqual(updates.latest(), expected)
                self.assertEqual("index" in calls, asked)

    def test_bounded_process(self):
        literal = "; $(example)"
        self.assertEqual(
            invoke([sys.executable, "-c", "import sys;print(sys.argv[1])", literal])[
                1
            ].strip(),
            literal.encode(),
        )
        for src, kwargs, diagnostic in [
            ("print('x'*100)", {"cap": 20}, "output_too_large"),
            ("import time;time.sleep(5)", {"timeout": 0.1}, "timeout"),
        ]:
            with self.assertRaises(ToolError) as exc:
                invoke([sys.executable, "-c", src], **kwargs)
            self.assertEqual(exc.exception.code, diagnostic)

    def test_git_token_reaches_github_and_gitlab_only(self):
        from appsec_cli.external import git_token_env

        with patch.dict(os.environ, {"GIT_TOKEN": "test-token", "OTHER": "kept"}):
            for args, kept in [
                (["https://github.com/OWNER/REPO"], True),
                (["--repo", "https://gitlab.com/GROUP/PROJECT.git"], True),
                ([".", "--commit", "HEAD"], True),
                (["--repo", "https://git.example.com/OWNER/REPO.git"], False),
                (["http://github.com/OWNER/REPO"], False),
                (["https://github.com.example.com/OWNER/REPO"], False),
                (
                    [
                        "--repo=https://github.com/OWNER/REPO",
                        "--requirements",
                        "https://wiki.example.com/catalog.yaml",
                    ],
                    False,
                ),
            ]:
                with self.subTest(args):
                    env = git_token_env(args)
                    if kept:
                        self.assertIsNone(env)
                    else:
                        self.assertNotIn("GIT_TOKEN", env)
                        self.assertEqual(env["OTHER"], "kept")

    def test_ctrl_c_gives_the_engine_time_to_finish(self):
        """attached() passes Ctrl-C on as SIGINT and waits before it stops the engine."""
        driver = (
            "import sys\n"
            "from appsec_cli.external import attached\n"
            "print(attached(sys.argv[2:], timeout=None, grace=float(sys.argv[1])))\n"
        )
        engines = {
            # Writes what it has on Ctrl-C, then ends as Python does.
            "finishes": "import pathlib,sys,time\n"
            "d=pathlib.Path(sys.argv[1])\n"
            "try:\n (d/'ready').write_text(str(__import__('os').getpid())); time.sleep(30)\n"
            "except KeyboardInterrupt:\n (d/'saved').touch(); sys.exit(130)\n",
            # Ignores SIGINT and has to be stopped.
            "hangs": "import os,pathlib,signal,sys,time\n"
            "signal.signal(signal.SIGINT, signal.SIG_IGN)\n"
            "d=pathlib.Path(sys.argv[1])\n"
            "(d/'ready').write_text(str(os.getpid())); time.sleep(30)\n",
        }
        for name, source in engines.items():
            with self.subTest(name), tempfile.TemporaryDirectory() as tmp:
                run = subprocess.Popen(
                    [sys.executable, "-c", driver, "0.5", sys.executable, "-c", source, tmp],
                    stdout=subprocess.PIPE,
                    text=True,
                )
                ready = Path(tmp, "ready")
                for _ in range(200):
                    if ready.is_file() and ready.read_text():
                        break
                    time.sleep(0.05)
                pid = int(ready.read_text())
                run.send_signal(signal.SIGINT)
                out, _ = run.communicate(timeout=20)
                self.assertEqual(out.strip(), "130")
                self.assertEqual(Path(tmp, "saved").is_file(), name == "finishes")
                with self.assertRaises(ProcessLookupError):
                    os.kill(pid, 0)
        self.assertEqual(
            attached([sys.executable, "-c", "raise SystemExit(4)"], timeout=None), 4
        )

    def test_external_engine_version_and_output(self):
        from appsec_cli.external import ExternalTool

        with tempfile.TemporaryDirectory() as tmp:
            executable = Path(tmp, "engine")
            executable.write_text(
                "#!/bin/sh\nif [ \"$1\" = --version ]; then echo 1.2; else echo '{}'; fi\n"
            )
            executable.chmod(0o700)
            with patch("appsec_cli.external.engine", return_value=str(executable)):
                self.assertEqual(ExternalTool("engine", "1.1").json([]), {})
                with self.assertRaises(ToolError) as exc:
                    ExternalTool("engine", "1.3").json([])
                self.assertEqual(exc.exception.code, "binary_version_unsupported")
        with self.assertRaises(ToolError):
            ExternalTool("nonexistent-appsec-unit-check").json([])

    def test_project_cannot_enable_plugins_or_set_endpoint(self):
        with (
            tempfile.TemporaryDirectory() as tmp,
            patch.dict(os.environ, {"XDG_CONFIG_HOME": tmp}),
        ):
            path = Path(tmp, "project.toml")
            for text in [
                '[plugins]\nadditional=["extra"]',
                '[llm]\nendpoint="http://localhost"',
            ]:
                path.write_text(text)
                with self.assertRaises(ToolError) as exc:
                    settings(path)
                self.assertEqual(exc.exception.code, "config_forbidden_key")
            path.unlink()
            os.mkfifo(path)
            with self.assertRaises(ToolError):
                settings(path)

    def test_configuration_errors_name_the_file_and_the_key(self):
        cwd = os.getcwd()
        self.addCleanup(os.chdir, cwd)
        with tempfile.TemporaryDirectory() as tmp:
            os.chdir(tmp)
            user = Path(tmp, ".config/appsec-cli/config.toml")
            user.parent.mkdir(parents=True)
            local = Path(tmp, ".appsec-cli.toml")
            chosen = Path(tmp, "ci.toml")
            env = {"HOME": tmp, "XDG_CONFIG_HOME": str(user.parents[1])}
            for files, message in [
                (
                    {local: "new_setting = true"},
                    "Unsupported key 'new_setting' in .appsec-cli.toml.",
                ),
                (
                    {local: 'fail_on = "hihg"'},
                    "Unknown threshold 'hihg' in .appsec-cli.toml.",
                ),
                ({local: "fail_on = ["}, "Cannot read .appsec-cli.toml."),
                (
                    {local: '[tools.score]\nlevel = "high"'},
                    "Only fail_on is supported in [tools.score] in .appsec-cli.toml.",
                ),
                (
                    {user: "[plugins]\nextra = []"},
                    "Invalid plugin configuration in ~/.config/appsec-cli/config.toml.",
                ),
                (
                    {chosen: "new_setting = 1"},
                    "Unsupported key 'new_setting' in ~/ci.toml.",
                ),
            ]:
                for path in (user, local, chosen):
                    path.write_text(files.get(path, ""))
                with self.subTest(message=message), patch.dict(os.environ, env):
                    with self.assertRaises(ToolError) as exc:
                        settings(chosen if chosen in files else None)
                    self.assertEqual(str(exc.exception), message)
            # A key from the repository must not put control characters on the terminal.
            escape = "\\" + "u001b"
            local.write_text(f'"{escape}[2J\\nx" = 1')
            with patch.dict(os.environ, env), self.assertRaises(ToolError) as exc:
                settings()
            self.assertTrue(str(exc.exception).isprintable(), str(exc.exception))
            self.assertIn(r"\x1b[2J\nx", str(exc.exception))
        with patch.object(Path, "home", side_effect=RuntimeError):
            self.assertEqual(shown(Path("/srv/ci.toml")), "/srv/ci.toml")

    def test_configured_threshold_replaces_the_tool_default(self):
        tool = ("analyze-threats", "never")
        self.assertEqual(Settings().threshold_for(*tool), ("never", False))
        configured = Settings(trusted={None: "high"}, local={None: "low"})
        self.assertEqual(configured.threshold_for(*tool), ("low", False))
        self.assertEqual(
            Settings(trusted={None: "high"}).threshold_for(*tool), ("high", False)
        )

    def test_project_file_only_tightens(self):
        cwd = os.getcwd()
        self.addCleanup(os.chdir, cwd)
        with tempfile.TemporaryDirectory() as tmp:
            os.chdir(tmp)
            user = Path(tmp, "appsec-cli/config.toml")
            user.parent.mkdir()
            local = Path(tmp, ".appsec-cli.toml")

            def threshold(user_text, local_text, tool_default=None):
                user.write_text(user_text)
                local.write_text(local_text)
                with patch.dict(os.environ, {"XDG_CONFIG_HOME": tmp}):
                    return settings().threshold_for("score", tool_default)

            self.assertEqual(
                threshold('fail_on = "high"', 'fail_on = "never"'), ("high", True)
            )
            self.assertEqual(
                threshold('fail_on = "high"', 'fail_on = "medium"'), ("medium", False)
            )
            self.assertEqual(threshold("", 'fail_on = "never"'), ("low", True))
            self.assertEqual(
                threshold("", '[tools.score]\nfail_on = "high"', "never"),
                ("high", False),
            )
            self.assertEqual(
                threshold('[tools.score]\nfail_on = "medium"', 'fail_on = "critical"'),
                ("medium", True),
            )
            self.assertEqual(threshold('fail_on = "high"', ""), ("high", False))
            trusted = Path(tmp, "trusted.toml")
            trusted.write_text('fail_on = "never"')
            with patch.dict(os.environ, {"XDG_CONFIG_HOME": tmp}):
                self.assertEqual(
                    settings(trusted).threshold_for("score", None), ("never", False)
                )
            local.write_text('[tools."*"]\nfail_on = "never"')
            with (
                patch.dict(os.environ, {"XDG_CONFIG_HOME": tmp}),
                self.assertRaises(ToolError),
            ):
                settings()
