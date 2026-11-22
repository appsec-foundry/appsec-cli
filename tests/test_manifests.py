from importlib import metadata
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from appsec_cli.catalog import discover
from appsec_cli.config import Settings
from appsec_cli.manifest_command import from_manifest
from appsec_cli.sdk import ToolError
from appsec_cli.manifests import Manifest, Source, usage


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
        # The suite itself is an installed package with one console script.
        suite = f"appsec-cli=={metadata.version('appsec-cli')}"
        spec = self.read(f'engine = "{suite}"')
        self.assertEqual(spec.name, "inventory")
        self.assertEqual(spec.args, ("--json",))
        with patch(
            "appsec_cli.manifest_command.ExternalTool.json", return_value={"items": 3}
        ) as call:
            repo = str(self.path.parent / "a;echo hi")
            handler = from_manifest(spec).handler
            self.assertEqual(handler(SimpleNamespace(args=[repo])).data, {"items": 3})
            call.assert_called_once_with(["--json", repo])
        with self.assertRaises(ToolError):
            from_manifest(self.read('engine = "appsec-cli==0.0.0.dev0"'))
        with self.assertRaises(ToolError):
            from_manifest(self.read(f'engine = "{suite}"\nbinary = "another-program"'))

    def test_invalid_definitions(self):
        for text in (
            'engine = "a>=1"',
            'engine = "a==1.*"',
            'engine = "a @ https://example.org/tool.whl"',
            'engine = "a==1"\nbinary = "../bin/tool"',
            'engine = "a==1"\nargs = "sh -c"',
            'engine = "a==1"\nshell = true',
            'engine = "a==1"\nargs = ["repo-profile", "{repo}", "--json"]',
            'engine = "a==1"\nforward_except = "--update"',
            'engine = "a==1"\nforward_except = ["update"]',
        ):
            with self.subTest(text=text), self.assertRaises(ValueError):
                self.read(text)

    def test_forward_except(self):
        spec = self.read('engine = "a==1"\nforward_except = ["--update", "-u"]')
        self.assertEqual(spec.forward_except, ("--update", "-u"))
        self.assertEqual(self.read('engine = "a==1"').forward_except, ())

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

    def test_enabled_and_source(self):
        spec = self.read('engine = "a==1"')
        self.assertTrue(spec.enabled)
        self.assertIsNone(spec.source)
        commit = "0123456789abcdef0123456789abcdef01234567"
        spec = self.read(
            'engine = "Team_Engine==1"\nenabled = false\n[source]\n'
            f'git = "https://git.example.com/engine.git"\ncommit = "{commit}"\n'
            'path = "engine"'
        )
        self.assertFalse(spec.enabled)
        self.assertEqual(
            spec.source,
            Source(
                "team-engine", "https://git.example.com/engine.git", commit, "engine"
            ),
        )
        git = 'git = "https://git.example.com/engine.git"\n'
        for text in (
            'enabled = "no"',
            "[source]\n" + git,
            "[source]\n" + git + 'commit = "main"',
            "[source]\n" + git + 'commit = "0123456"',
            f'[source]\ngit = "--upload-pack=touch x"\ncommit = "{commit}"',
            f'[source]\n{git}commit = "{commit}"\npath = "../core"',
            f'[source]\n{git}commit = "{commit}"\npath = "/srv/engine"',
            f'[source]\n{git}commit = "{commit}"\npackage = "other"',
        ):
            with self.subTest(text=text), self.assertRaises(ValueError):
                self.read('engine = "a==1"\n' + text)

    def test_symlink_rejected(self):
        self.path.symlink_to(self.path.parent / "missing")
        with self.assertRaises(ValueError):
            Manifest.read(self.path)


class DefaultOff(unittest.TestCase):
    """A tool shipped with enabled = false waits for [plugins].additional."""

    def statuses(self, **selection):
        def entry(name, group, value="appsec_plugin_team"):
            return metadata.EntryPoint(name, value, group)

        dists = {
            "appsec-cli": SimpleNamespace(
                entry_points=[
                    entry("team", "appsec_cli.bundle"),
                    entry("team", "appsec_cli.optional"),
                    entry("inventory", "appsec_cli.manifests", "appsec_suite.tools"),
                    entry("inventory", "appsec_cli.optional", "appsec_suite.tools"),
                ]
            ),
            "appsec-plugin-team": SimpleNamespace(
                entry_points=[
                    entry("team", "appsec_cli.tools", "appsec_plugin_team:run")
                ],
                version="1.0",
                metadata={"Summary": "Team tool."},
            ),
        }

        def distribution(name):
            if name not in dists:
                raise metadata.PackageNotFoundError(name)
            return dists[name]

        cfg = Settings(**{key: set(names) for key, names in selection.items()})
        with patch("appsec_cli.catalog.metadata.distribution", distribution):
            tools = discover(cfg)
        return tools["team"].status, tools["inventory"].status

    def test_off_until_enabled(self):
        self.assertEqual(self.statuses(), ("disabled", "disabled"))
        self.assertEqual(self.statuses(additional=["team"]), ("unchecked", "disabled"))
        self.assertEqual(
            self.statuses(additional=["team"], disabled=["team"]),
            ("disabled", "disabled"),
        )
