"""Exercise a real pipx install and upgrade against a temporary, exclusively local package index.

Two releases built here from fixture tools test the upgrade: an engine update, an
adapter update, an added and a dropped tool, a tool.toml wrapper, deactivation
and plugins added with pipx inject. They need none of the tools a team ships.
The update to the release in dist/ then checks every tool of that release
through the installed CLI.
"""

import argparse
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

try:
    import tomllib
except ImportError:  # Python 3.10
    import tomli as tomllib

from packaging.version import Version

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location(
    "manifests", ROOT / "core/src/appsec_cli/manifests.py"
)
manifests = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(manifests)
VERSION = re.compile(r'(?m)^version = ".*"$')


def official(root=ROOT):
    """The tools of this checkout, and whether a release turns each one on."""
    found = {}
    for folder in sorted((root / "tools").iterdir()):
        if not folder.is_dir() or folder.name.startswith(("_", ".")):
            continue
        if (folder / "tool.toml").is_file():
            found[folder.name] = manifests.Manifest.read(folder / "tool.toml").enabled
            continue
        doc = tomllib.loads((folder / "pyproject.toml").read_text())
        table = doc.get("tool", {}).get("appsec-cli", {})
        found[folder.name] = table.get("enabled", True)
    return found


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--wheels", type=Path, required=True, help="External dependency wheels"
    )
    parser.add_argument("--release", type=Path, default=ROOT / "dist")
    args = parser.parse_args()
    suite = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["version"]
    if Version(suite) <= Version("0.0.2"):
        raise SystemExit("The suite needs a version above the test releases, 0.0.2.")
    with tempfile.TemporaryDirectory(prefix="appsec-pipx-") as tmp:
        work = Path(tmp)
        index = work / "index"
        index.mkdir()
        for wheel in args.release.glob("appsec_cli_core-*.whl"):
            shutil.copy(wheel, index)
        config = work / "cfg" / "appsec-cli"
        config.mkdir(parents=True)
        env = {
            **os.environ,
            "PIPX_HOME": str(work / "pipx"),
            "PIPX_BIN_DIR": str(work / "bin"),
            "XDG_CONFIG_HOME": str(config.parent),
            "PIP_NO_INDEX": "1",
            "PIP_FIND_LINKS": index.as_uri() + " " + args.wheels.resolve().as_uri(),
            "PIP_NO_CACHE_DIR": "1",
            "PIP_DISABLE_PIP_VERSION_CHECK": "1",
        }

        def run(*argv, codes=(0,)):
            p = subprocess.run(
                argv, cwd=work, env=env, text=True, capture_output=True, timeout=180
            )
            if p.returncode not in codes:
                raise RuntimeError(
                    f"{argv} exited {p.returncode}\n{p.stdout}\n{p.stderr}"
                )
            return p.stdout

        def build(project):
            run(
                sys.executable,
                "-m",
                "pip",
                "wheel",
                "--no-deps",
                "--no-build-isolation",
                "--wheel-dir",
                index,
                project,
            )

        def engine(version):
            """A JSON engine with a console script, as a team's engine is one."""
            target = work / f"engine-{version}"
            (target / "fixture_engine").mkdir(parents=True)
            (target / "pyproject.toml").write_text(
                '[build-system]\nrequires = ["setuptools"]\n'
                'build-backend = "setuptools.build_meta"\n\n'
                f'[project]\nname = "appsec-fixture-engine"\nversion = "{version}"\n\n'
                '[project.scripts]\nfixture-engine = "fixture_engine:main"\n'
            )
            (target / "fixture_engine/__init__.py").write_text(
                "import json\nimport sys\n\n\ndef main():\n"
                f"    print(json.dumps({{'version': '{version}', 'args': sys.argv[1:]}}))\n"
            )
            build(target)

        def from_template(name, command=None, version=None):
            """Copy tools/_template and rename it as docs/writing-a-tool.md describes."""
            module = "appsec_plugin_" + name.replace("-", "_")
            target = work / "plugins" / f"{name}-{version or 'template'}"
            shutil.copytree(
                ROOT / "tools/_template",
                target,
                ignore=shutil.ignore_patterns("*.egg-info", "__pycache__", "build"),
            )
            (target / "src/appsec_plugin_template").rename(target / "src" / module)
            entry = f"{name}.{command}" if command else name
            for path in (
                target / "pyproject.toml",
                target / "src" / module / "__init__.py",
                target / "tests/test_plugin.py",
            ):
                text = path.read_text().replace("appsec_plugin_template", module)
                text = text.replace('"template" =', f'"{entry}" =')
                path.write_text(text.replace("template", name))
            if version:
                pyproject = target / "pyproject.toml"
                text = pyproject.read_text()
                pyproject.write_text(VERSION.sub(f'version = "{version}"', text, 1))
            build(target)
            return target

        def release(version, tools):
            """A suite release with these tool directories: adapters or tool.toml text."""
            target = work / f"suite-{version}"
            shutil.copytree(ROOT / "src/appsec_suite", target / "src/appsec_suite")
            shutil.copytree(ROOT / "skills", target / "skills")
            shutil.copy(ROOT / "setup.py", target)
            (target / "core/src/appsec_cli").mkdir(parents=True)
            shutil.copy(ROOT / "core/pyproject.toml", target / "core")
            shutil.copy(
                ROOT / "core/src/appsec_cli/manifests.py",
                target / "core/src/appsec_cli",
            )
            folder = target / "tools"
            folder.mkdir()
            shutil.copy(ROOT / "tools/__init__.py", folder)
            for name, source in tools.items():
                (folder / name).mkdir()
                if isinstance(source, str):
                    (folder / name / "tool.toml").write_text(source)
                else:
                    shutil.copy(source / "pyproject.toml", folder / name)
            text = (ROOT / "pyproject.toml").read_text()
            (target / "pyproject.toml").write_text(
                VERSION.sub(f'version = "{version}"', text, 1)
            )
            build(target)

        def inventory(version):
            return f'engine = "appsec-fixture-engine=={version}"\nargs = ["--json"]\n'

        # Release A: an adapter that release B updates, one that B drops, one
        # the user disables, and a tool that is only a tool.toml.
        engine("1.0.0")
        engine("2.0.0")
        lint = from_template("team-lint")
        release(
            "0.0.1",
            {
                "repo-inventory": inventory("1.0.0"),
                "team-lint": lint,
                "team-report": from_template("team-report"),
                "team-score": from_template("team-score", version="0.1.0"),
            },
        )
        run("pipx", "install", "appsec-cli")
        cli = work / "bin/appsec-cli"
        cfg = config / "config.toml"

        def result(*args, codes=(0,)):
            return json.loads(run(cli, "--format", "json", *args, codes=codes))

        # The suite build collects the examples; the CLI shows them unloaded.
        listing = {t["name"]: t for t in result("tools", "list")["tools"]}
        first = listing["team-report"]["usage"][0]["examples"][0]["run"]
        assert first.startswith("appsec-cli team-report "), listing
        assert result("team-report", "sample")["data"] == {"characters": 6}
        wrapped = result("repo-inventory", "x")
        assert wrapped["data"] == {"version": "1.0.0", "args": ["--json", "x"]}, wrapped
        assert wrapped["run"]["tool_version"] == "1.0.0", wrapped
        assert (
            result("tools", "describe", "repo-inventory")["definitions"][0]["command"]
            == "repo-inventory"
        )
        cfg.write_text('[plugins]\ndisabled=["team-lint","repo-inventory"]\n')
        run(cli, "team-lint", "sample", codes=(2,))
        run(cli, "repo-inventory", "x", codes=(2,))
        cfg.write_text('[plugins]\ndisabled=["team-lint"]\n')

        # Release B: a new engine and adapter version, an added and a dropped tool.
        release(
            "0.0.2",
            {
                "repo-inventory": inventory("2.0.0"),
                "team-lint": lint,
                "team-new": from_template("team-new"),
                "team-score": from_template("team-score", version="0.2.0"),
            },
        )
        update = result("update", "--yes")
        assert update["before"]["version"] == "0.0.1", update
        assert update["after"]["version"] == "0.0.2", update
        assert update["before"]["tools"]["team-score"] == "0.1.0", update
        assert update["after"]["tools"]["team-score"] == "0.2.0", update
        assert update["after"]["tools"]["repo-inventory"] == "2.0.0", update
        assert "team-new" in update["after"]["tools"], update
        assert "team-report" not in update["after"]["tools"], update
        assert run(cli, "--version").splitlines()[0] == "appsec-cli 0.0.2"
        wrapped = result("repo-inventory", "x")
        assert wrapped["data"]["version"] == "2.0.0", wrapped
        assert wrapped["run"]["tool_version"] == "2.0.0", wrapped
        assert result("team-score", "sample")["status"] == "ok"
        statuses = {
            t["name"]: t["status"]
            for t in result("tools", "list", "--all", "--check")["tools"]
        }
        assert statuses["team-lint"] == "disabled" and statuses["team-new"] == "ready"
        assert "team-report" not in statuses
        run(cli, "team-lint", "--help", codes=(2,))
        run(cli, "team-report", "sample", codes=(2,))  # its wheel is still installed

        for name, command in [("team-findings", None), ("team-group", "summary")]:
            from_template(name, command)
            run("pipx", "inject", "appsec-cli", "appsec-plugin-" + name)
        venv_python = work / "pipx/venvs/appsec-cli/bin/python"
        run(
            venv_python,
            "-m",
            "unittest",
            "discover",
            "-s",
            work / "plugins/team-findings-template/tests",
        )
        cfg.write_text('[plugins]\nadditional=["team-group","team-findings"]\n')
        assert result("team-group", "summary", "example")["data"]["characters"] == 7
        assert (
            result("--fail-on", "info", "team-findings", "TODO", codes=(1,))["counts"][
                "info"
            ]
            == 1
        )
        assert result("team-lint", "sample")["status"] == "ok"  # enabled again
        assert all(
            t["status"] == "ready" for t in result("tools", "list", "--check")["tools"]
        )

        # The release in dist/: every one of its tools through the installed CLI.
        for wheel in args.release.glob("*.whl"):
            shutil.copy(wheel, index)
        cfg.write_text("")
        update = result("update", "--yes")
        expected = official()
        assert update["after"]["version"] == suite, update
        assert set(update["after"]["tools"]) == set(expected), update
        assert run(cli, "--version").splitlines()[0] == f"appsec-cli {suite}"
        statuses = {
            t["name"]: t["status"]
            for t in result("tools", "list", "--all", "--check")["tools"]
        }
        assert statuses == {
            name: "ready" if on else "disabled" for name, on in expected.items()
        }, statuses
        optional = sorted(name for name, on in expected.items() if not on)
        cfg.write_text(f"[plugins]\nadditional = {json.dumps(optional)}\n")
        tools = result("tools", "list", "--check")["tools"]
        assert {t["name"] for t in result()["tools"]} == set(expected)
        for tool in tools:
            assert tool["status"] == "ready", tool
            described = result("tools", "describe", tool["name"])["definitions"]
            assert [d["command"] for d in described] == tool["commands"], tool
            for command in tool["commands"]:
                assert f"appsec-cli {command}" in run(cli, *command.split(), "--help")
        print(
            "pipx install, upgrade, engine update, discovery, deactivation and"
            f" standalone plugins passed. Release {suite} ready: {len(tools)} tool(s)."
        )


if __name__ == "__main__":
    main()
