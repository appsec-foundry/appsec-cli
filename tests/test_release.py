import importlib.util
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location(
    "build_release", ROOT / "scripts/build_release.py"
)
build_release = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(build_release)


class ReleaseVersions(unittest.TestCase):
    def test_changes_need_new_versions(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)

            def git(*args):
                subprocess.run(
                    [
                        "git",
                        "-C",
                        tmp,
                        "-c",
                        "user.name=t",
                        "-c",
                        "user.email=t@example.invalid",
                        *args,
                    ],
                    check=True,
                    capture_output=True,
                )

            def project(folder, version):
                folder.mkdir(parents=True, exist_ok=True)
                (folder / "pyproject.toml").write_text(
                    f'[project]\nname = "x"\nversion = "{version}"\n'
                )

            for folder in (root, root / "core", root / "tools/score"):
                project(folder, "1.0.0")
            git("init", "-q")
            git("add", ".")
            git("commit", "-qm", "release")
            git("tag", "v1.0.0")
            build_release.check_versions(root)
            (root / "tools/score/engine.py").write_text("changed = True\n")
            git("add", ".")
            git("commit", "-qm", "change")
            with self.assertRaisesRegex(SystemExit, "already released"):
                build_release.check_versions(root)
            project(root, "1.0.1")
            with self.assertRaisesRegex(SystemExit, "tools/score"):
                build_release.check_versions(root)
            project(root / "tools/score", "1.0.1")
            build_release.check_versions(root)
