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


class EngineCheckout(unittest.TestCase):
    def test_checks_out_the_pinned_commit_from_a_git_url(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp, "engine")
            repo.mkdir()

            def git(*args):
                return subprocess.run(
                    [
                        "git",
                        "-C",
                        str(repo),
                        "-c",
                        "user.name=t",
                        "-c",
                        "user.email=t@example.invalid",
                        *args,
                    ],
                    check=True,
                    capture_output=True,
                    text=True,
                ).stdout.strip()

            git("init", "-q")
            (repo / "engine.py").write_text("pinned = True\n")
            git("add", ".")
            git("commit", "-qm", "pinned")
            pinned = git("rev-parse", "HEAD")
            (repo / "engine.py").write_text("pinned = False\n")
            git("commit", "-qam", "later")

            target = Path(tmp, "checkout")
            build_release.checkout(repo.as_uri(), pinned, target)
            self.assertEqual((target / "engine.py").read_text(), "pinned = True\n")
            with self.assertRaises(subprocess.CalledProcessError):
                build_release.checkout(repo.as_uri(), "0" * 40, Path(tmp, "unknown"))


class EngineSources(unittest.TestCase):
    def test_tool_directories_name_the_sources(self):
        commit = "0123456789abcdef0123456789abcdef01234567"
        adapter = (
            '[project]\nname = "appsec-plugin-NAME"\nversion = "1"\n'
            'dependencies = ["appsec-cli-core==1", "appsec-security-score==0.3.3"]\n'
            "[tool.appsec-cli.source]\n"
            'package = "appsec-security-score"\n'
            'git = "https://git.example.com/tools.git"\n'
            f'commit = "{commit}"\npath = "security-score"\n'
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)

            def tool(name, text, kind="pyproject.toml"):
                folder = root / "tools" / name
                folder.mkdir(parents=True, exist_ok=True)
                (folder / kind).write_text(text.replace("NAME", name))

            tool("score", adapter)
            tool("score-change", adapter)
            tool("plain", '[project]\nname = "appsec-plugin-plain"\nversion = "1"\n')
            tool("_draft", adapter.replace(commit, "main"))
            tool(
                "inventory",
                'engine = "team-engine==1"\n[source]\n'
                f'git = "https://git.example.com/engine.git"\ncommit = "{commit}"\n',
                "tool.toml",
            )
            found = build_release.sources(root)
            self.assertEqual(sorted(found), ["appsec-security-score", "team-engine"])
            self.assertEqual(found["appsec-security-score"].path, "security-score")

            mirror = build_release.sources(
                root, ["appsec-security-score=/srv/mirror/tools"]
            )
            self.assertEqual(mirror["appsec-security-score"].git, "/srv/mirror/tools")
            self.assertEqual(mirror["appsec-security-score"].commit, commit)
            for pair in ("unknown=/srv/mirror", "appsec-security-score="):
                with self.subTest(pair=pair), self.assertRaises(SystemExit):
                    build_release.sources(root, [pair])

            for text, message in (
                (adapter.replace(commit, "f" * 40), "different source"),
                (adapter.replace("==0.3.3", ">=0.3"), "pin"),
                (adapter.replace(commit, "main"), "commit hash"),
            ):
                tool("score-change", text)
                with self.subTest(message=message):
                    with self.assertRaisesRegex(SystemExit, message):
                        build_release.sources(root)
