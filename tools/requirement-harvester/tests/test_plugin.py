"""requirement-harvester adapter: the Harvester commands it starts and what they return.

Run with the Python of an installed suite:
python -m unittest discover -s tools/requirement-harvester/tests
"""

import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import click
from appsec_cli import ToolError
from appsec_plugin_requirement_harvester import commands

# The minimal configuration from the Harvester's README.
CONFIG = """\
config-version: 1
output:
  catalog: out/requirements.oscal.yaml
  report: out/report.json
  title: Company Requirements
  version: 1.0.0
sources:
- id: company
  title: Company Requirements
  start-urls:
  - https://wiki.example.org/requirements/engineering
  crawl:
    allowed-origins: [https://wiki.example.org]
    allowed-path-prefixes: [/requirements/]
    max-depth: 2
  auth:
    mode: none
  extraction:
    content-selector: main
    rules:
    - id: list-items
      strategy: blocks
      item-selector: ul.requirements > li
      fields:
        original-id: {attribute: id}
        statement: {}
"""


def call(command, *args):
    return command.handler(SimpleNamespace(args=list(args)))


def exits(code, stderr):
    """An invoke() that ends with code after writing stderr."""

    def invoke(argv, **kwargs):
        kwargs["stderr"].extend(stderr)
        return code, b""

    return invoke


class Harvester(unittest.TestCase):
    def setUp(self):
        patcher = patch.object(commands, "engine", return_value="engine")
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_run_passes_its_arguments(self):
        out = (
            b'{"status": "complete", "requirements": 3, "catalogs": 1, "dry-run": true}'
        )
        with patch.object(commands, "invoke", return_value=(0, out)) as invoke:
            result = call(commands.run, "--config", "c.yaml", "--dry-run")
        self.assertEqual(
            invoke.call_args.args[0],
            ["engine", "run", "--config", "c.yaml", "--dry-run"],
        )
        self.assertEqual(invoke.call_args.kwargs["timeout"], commands.LIMIT)
        self.assertEqual(result.data["requirements"], 3)
        self.assertEqual(result.summary, "Dry run complete; no catalog written.")

    def test_terminal_runs_the_engine(self):
        terminal = commands.run.passthrough(SimpleNamespace(args=["--config", "c"]))
        self.assertEqual(terminal.argv, ["engine", "run", "--config", "c"])
        self.assertEqual(terminal.timeout, commands.LIMIT)

    def test_git_token_stays_with_its_hosts(self):
        secrets = {"GIT_TOKEN": "git-secret", "HARVEST_TOKEN": "harvest-secret"}
        with (
            patch.dict(os.environ, secrets),
            patch.object(commands, "invoke", return_value=(0, b"")) as invoke,
        ):
            call(commands.validate, "--config", "c.yaml")
            terminal = commands.login.passthrough(SimpleNamespace(args=[]))
        for env in (invoke.call_args.kwargs["env"], terminal.env):
            self.assertNotIn("GIT_TOKEN", env)
            self.assertEqual(env["HARVEST_TOKEN"], "harvest-secret")

    def test_failures_by_exit_code(self):
        error = b'{"error": "Sign-in expired.", "exit-code": 3}\n'
        crash = (
            b"Processing error; no diagnostic content or credentials were printed.\n"
        )
        for code, stderr, expected, message in (
            (3, error, "auth_failed", "Sign-in expired."),
            (4, crash, "harvest_failed", crash.decode().strip()),
            (5, error, "export_failed", "Sign-in expired."),
            (
                130,
                b"",
                "harvest_failed",
                "The Harvester could not complete the command.",
            ),
        ):
            with (
                patch.object(commands, "invoke", side_effect=exits(code, stderr)),
                self.assertRaises(ToolError) as failed,
            ):
                call(commands.run, "--config", "c.yaml")
            self.assertEqual(failed.exception.code, expected)
            self.assertEqual(str(failed.exception), message)

    def test_invalid_configuration_is_a_usage_error(self):
        stderr = b'{"error": "Source IDs must be unique.", "exit-code": 2}\n'
        with (
            patch.object(commands, "invoke", side_effect=exits(2, stderr)),
            self.assertRaises(click.UsageError) as refused,
        ):
            call(commands.run, "--config", "c.yaml")
        self.assertEqual(
            refused.exception.format_message(), "Source IDs must be unique."
        )

    def test_login_needs_the_terminal(self):
        with (
            patch.object(commands, "invoke") as invoke,
            self.assertRaises(click.UsageError),
        ):
            call(commands.login, "--config", "c.yaml", "--source", "company")
        invoke.assert_not_called()


class Engine(unittest.TestCase):
    """The installed Harvester, without network access."""

    def test_validate(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp, "requirements.yaml")
            config.write_text(CONFIG)
            self.assertEqual(
                call(commands.validate, "--config", str(config)).status, "ok"
            )
            config.write_text("config-version: 1\n")
            with self.assertRaises(click.UsageError) as refused:
                call(commands.validate, "--config", str(config))
        self.assertIn("violates the schema", refused.exception.format_message())
        with self.assertRaises(click.UsageError) as refused:
            call(commands.run)
        self.assertIn(
            "requirement-harvester run: the following arguments are required: --config",
            refused.exception.format_message(),
        )


if __name__ == "__main__":
    unittest.main()
