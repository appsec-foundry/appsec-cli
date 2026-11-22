"""appsec-analyzer adapter: the Analyzer commands it starts and what they return.

Run with the Python of an installed suite:
python -m unittest discover -s tools/appsec-analyzer/tests
"""

import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import click
from appsec_plugin_appsec_analyzer import commands


def run(command, *args):
    return command.handler(SimpleNamespace(args=list(args)))


class Analyzer(unittest.TestCase):
    def test_export_passes_its_arguments(self):
        args = ("--assessment", "a", "--output", "b", "--formats", "sarif")
        with (
            patch.object(commands, "engine", return_value="engine"),
            patch.object(commands, "invoke", return_value=(0, b"")) as call,
        ):
            result = run(commands.export, *args)
        self.assertEqual(call.call_args.args[0], ["engine", "export", *args])
        self.assertEqual(result.summary, "Assessment exported.")
        with self.assertRaises(click.UsageError) as exc:
            run(commands.export, "--bogus")
        self.assertIn(
            "appsec-analyzer export: the following arguments are required",
            exc.exception.format_message(),
        )

    def test_repo_profile(self):
        with tempfile.TemporaryDirectory() as tmp:
            subprocess.run(["git", "init", "-q", tmp], check=True)
            Path(tmp, "README.md").write_text("Initial\n")
            result = run(commands.profile, tmp)
        self.assertEqual(result.status, "ok")
        self.assertIsInstance(result.data, dict)


if __name__ == "__main__":
    unittest.main()
