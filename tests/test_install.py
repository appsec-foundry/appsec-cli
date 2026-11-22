import importlib.util
import io
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("install", ROOT / "scripts/install.py")
install = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(install)

PYTHON = [sys.executable, "-c"]


class Installer(unittest.TestCase):
    def installer(self, log=None, **changes):
        args = dict(
            lock="requirements-linux-py310.lock",
            wheels=".wheelhouse",
            source=[],
            release=False,
            no_install=False,
            verbose=False,
        )
        args.update(changes)
        out = io.StringIO()
        installer = install.Installer(
            SimpleNamespace(**args), install.Screen(out, env={}), log
        )
        self.addCleanup(installer.close)
        return installer, out

    def test_prints_one_plain_line_per_step_off_a_terminal(self):
        installer, out = self.installer()
        self.assertTrue(installer.step("Build", lambda: "2 engines · 5 packages"))
        self.assertEqual(out.getvalue(), "  ✓ Build          2 engines · 5 packages\n")

    def test_a_failed_step_shows_its_error_a_hint_and_the_log(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp, "install.log")
            installer, out = self.installer(log)
            code = (
                "print('Collecting x');print('ERROR: No matching distribution');exit(1)"
            )
            ok = installer.step(
                "Dependencies", lambda: installer.run(PYTHON + [code], "downloading")
            )
            installer.close()
            shown = out.getvalue()
            self.assertFalse(ok)
            self.assertIn("✗ Dependencies   downloading failed", shown)
            self.assertIn("    ERROR: No matching distribution", shown)
            self.assertNotIn("Collecting x", shown)
            self.assertIn("pip cannot reach the package index", shown)
            self.assertIn("install.log", shown)
            self.assertIn("Collecting x", log.read_text())

    def test_removes_credentials_from_urls_in_the_log_and_on_screen(self):
        url = "https://deploy:s3cret@gitlab.example.com/appsec/engine.git"
        for verbose in (False, True):
            with self.subTest(verbose=verbose), tempfile.TemporaryDirectory() as tmp:
                log = Path(tmp, "install.log")
                installer, out = self.installer(log, verbose=verbose)
                code = "import sys; print('fatal: unable to access', sys.argv[1])"
                installer.run(PYTHON + [code, url], "cloning")
                installer.close()
                shown = out.getvalue() + log.read_text()
                self.assertNotIn("s3cret", shown)
                self.assertIn("https://***@gitlab.example.com/appsec/engine.git", shown)

    def test_a_missing_tool_stops_the_installation_before_any_command(self):
        installer, out = self.installer()
        which = shutil.which
        missing = mock.patch.object(
            install.shutil,
            "which",
            lambda tool: None if tool == "pipx" else which(tool),
        )
        with missing, mock.patch.object(installer, "run") as run:
            self.assertEqual(installer.main(), 1)
        run.assert_not_called()
        self.assertIn(
            "pipx: install it as described at https://pipx.pypa.io", out.getvalue()
        )

    def test_keeps_hash_checking_and_installs_without_a_package_index(self):
        installer, _ = self.installer()
        version = ["appsec-cli 1.0.0", "  score  1.0.0"]
        folder = mock.patch.object(install, "pipx_bin_dir", return_value=Path("/x"))
        with folder, mock.patch.object(installer, "run", return_value=version) as run:
            installer.dependencies()
            summary = installer.install()
        download, deps, pipx = (call.args[0] for call in run.call_args_list[1:4])
        self.assertIn("--require-hashes", download)
        self.assertIn("--only-binary=:all:", download)
        self.assertIn("--require-hashes", deps)
        self.assertIn("--no-index", deps)
        self.assertEqual(pipx[:2], ["pipx", "install"])
        self.assertEqual(run.call_args_list[3].kwargs["env"]["PIP_NO_INDEX"], "1")
        self.assertEqual(summary, "appsec-cli 1.0.0 · 1 tool")


if __name__ == "__main__":
    unittest.main()
