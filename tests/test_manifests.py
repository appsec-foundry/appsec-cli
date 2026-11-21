from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from appsec_cli.manifest_command import from_manifest
from appsec_cli.sdk import ToolError
from appsec_cli.manifests import Manifest, usage


class ManifestTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.path = Path(tmp.name, "inventory", "tool.toml")
        self.path.parent.mkdir()

    def read(self, text):
        self.path.write_text(text)
        return Manifest.read(self.path)

    def test_one_field_and_version_check(self):
        spec = self.read('engine = "appsec-analyzer==0.1.0a0"')
        self.assertEqual(spec.name, "inventory")
        self.assertEqual(spec.args, ("{repo}", "--json"))
        with patch(
            "appsec_cli.manifest_command.ExternalTool.json", return_value={"items": 3}
        ) as call:
            repo = self.path.parent / "a;echo hi"
            self.assertEqual(from_manifest(spec).handler(repo).data, {"items": 3})
            call.assert_called_once_with([str(repo), "--json"])
        with self.assertRaises(ToolError):
            from_manifest(self.read('engine = "appsec-analyzer==0.0.1"'))
        with self.assertRaises(ToolError):
            from_manifest(
                self.read(
                    'engine = "appsec-analyzer==0.1.0a0"\nbinary = "another-program"'
                )
            )

    def test_invalid_definitions(self):
        for text in (
            'engine = "a>=1"',
            'engine = "a==1.*"',
            'engine = "a @ https://example.org/tool.whl"',
            'engine = "a==1"\nbinary = "../bin/tool"',
            'engine = "a==1"\nargs = "sh -c"',
            'engine = "a==1"\nshell = true',
        ):
            with self.subTest(text=text), self.assertRaises(ValueError):
                self.read(text)

    def test_examples(self):
        spec = self.read(
            'engine = "a==1"\n'
            'examples = [{ run = "inventory .", what = "Inventory this repository" }]'
        )
        self.assertEqual(
            spec.examples,
            ({"run": "inventory .", "what": "Inventory this repository"},),
        )
        for text in (
            'examples = [{ run = "other .", what = "Another tool" }]',
            'examples = [{ run = "inventory-all", what = "Prefix only" }]',
            'examples = [{ run = "inventory", what = "" }]',
            'examples = [{ run = "inventory\\nrm -rf", what = "Two lines" }]',
            'examples = [{ run = "inventory", what = "x", shell = true }]',
            'examples = "inventory"',
        ):
            with self.subTest(text=text), self.assertRaises(ValueError):
                self.read('engine = "a==1"\n' + text)

    def test_adapter_usage(self):
        export = {"run": "tool export a b", "what": "Export a report"}
        found = usage(
            "tool",
            {"commands": {"export": {"summary": "Export.", "examples": [export]}}},
            {"export", "list"},
        )
        self.assertEqual(
            found, {"export": {"summary": "Export.", "examples": [export]}}
        )
        root = usage("tool", {"examples": [{"run": "tool .", "what": "Run"}]}, {""})
        self.assertEqual(root[""]["examples"][0]["run"], "tool .")
        many = [{"run": "tool", "what": "Run"}] * 6
        for table, commands in (
            ({"examples": []}, {"export"}),
            ({"commands": {"missing": {}}}, {"export"}),
            ({"commands": {"export": {"summary": "One\nTwo"}}}, {"export"}),
            (
                {"commands": {"export": {"examples": [export | {"run": "tool list"}]}}},
                {"export", "list"},
            ),
            ({"examples": many}, {""}),
            ({"other": 1}, {""}),
        ):
            with self.subTest(table=table), self.assertRaises(ValueError):
                usage("tool", table, commands)

    def test_symlink_rejected(self):
        self.path.symlink_to(self.path.parent / "missing")
        with self.assertRaises(ValueError):
            Manifest.read(self.path)
