"""Exercise a real pipx upgrade against a temporary, exclusively local package index."""

import argparse
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location(
    "build_release", ROOT / "scripts/build_release.py"
)
build_release = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(build_release)
HISTORIC_SCORE = "0294a9338caaf17d531bb222e86c353b81d60828"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--wheels", type=Path, required=True, help="External dependency wheels"
    )
    parser.add_argument(
        "--source",
        action="append",
        default=[],
        metavar="PACKAGE=URL",
        help="Another trusted Git URL or checkout for an engine",
    )
    parser.add_argument("--release", type=Path, default=ROOT / "dist")
    args = parser.parse_args()
    score = build_release.sources(overrides=args.source)["appsec-security-score"].git
    with tempfile.TemporaryDirectory(prefix="appsec-pipx-") as tmp:
        work = Path(tmp)
        index = work / "index"
        index.mkdir()
        for wheel in args.release.glob("*.whl"):
            if not wheel.name.startswith(
                (
                    "appsec_cli-",
                    "appsec_plugin_security_score-",
                    "appsec_security_score-",
                )
            ):
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

        checkout = work / "tools"
        run(
            "git",
            "-c",
            "core.hooksPath=/dev/null",
            "clone",
            "--no-local",
            "--no-checkout",
            "--",
            # Commands run in the temporary directory, so resolve a local path.
            Path(score).resolve() if Path(score).exists() else score,
            checkout,
        )
        run(
            "git",
            "-C",
            checkout,
            "-c",
            "core.hooksPath=/dev/null",
            "checkout",
            "--detach",
            HISTORIC_SCORE,
        )
        build(checkout / "security-score")

        def from_template(name, command=None):
            """Copy tools/_template and rename it as docs/writing-a-tool.md describes."""
            module = "appsec_plugin_" + name.replace("-", "_")
            target = work / name
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
            build(target)
            return target

        old = work / "old-plugin"
        shutil.copytree(
            ROOT / "tools/security-score/src",
            old / "src",
            ignore=shutil.ignore_patterns("*.egg-info", "__pycache__"),
        )
        (old / "pyproject.toml").write_text(
            (ROOT / "tools/security-score/pyproject.toml")
            .read_text()
            .replace('version = "0.1.0"', 'version = "0.0.9"')
            .replace("score==0.3.3", "score==0.3.2")
        )
        build(old)

        # Release A: an older score adapter, an official team-report tool that
        # release B drops, no verifier yet, and a tool that is only a tool.toml.
        old_suite = work / "old-suite"
        shutil.copytree(ROOT / "src/appsec_suite", old_suite / "src/appsec_suite")
        shutil.copytree(ROOT / "skills", old_suite / "skills")
        shutil.copy(ROOT / "setup.py", old_suite)
        (old_suite / "core/src/appsec_cli").mkdir(parents=True)
        shutil.copy(ROOT / "core/pyproject.toml", old_suite / "core")
        shutil.copy(
            ROOT / "core/src/appsec_cli/manifests.py", old_suite / "core/src/appsec_cli"
        )
        tools = old_suite / "tools"
        tools.mkdir()
        shutil.copy(ROOT / "tools/__init__.py", tools)
        adapters = {
            "analyze-threats": ROOT / "tools/analyze-threats",
            "appsec-analyzer": ROOT / "tools/appsec-analyzer",
            "security-score": old,
            "team-report": from_template("team-report"),
        }
        for name, source in adapters.items():
            (tools / name).mkdir()
            shutil.copy(source / "pyproject.toml", tools / name)
        (tools / "repo-inventory").mkdir()
        (tools / "repo-inventory/tool.toml").write_text(
            'engine = "appsec-analyzer==0.1.0a0"\nargs = ["repo-profile", "--json"]\n'
        )
        (old_suite / "pyproject.toml").write_text(
            (ROOT / "pyproject.toml")
            .read_text()
            .replace('version = "0.1.0"', 'version = "0.0.9"')
        )
        build(old_suite)
        run("pipx", "install", "appsec-cli")
        cli = work / "bin/appsec-cli"

        def result(*args, codes=(0,)):
            return json.loads(run(cli, "--format", "json", *args, codes=codes))

        assert result("team-report", "sample")["data"] == {"characters": 6}
        cfg = config / "config.toml"
        cfg.write_text('[plugins]\ndisabled=["appsec-analyzer"]\n')
        fixture = work / "repo"
        run("git", "init", "-q", fixture)
        (fixture / "README.md").write_text("Initial\n")

        def commit(msg):
            run("git", "-C", fixture, "add", ".")
            run(
                "git",
                "-C",
                fixture,
                "-c",
                "user.name=Test",
                "-c",
                "user.email=test@example.invalid",
                "commit",
                "-qm",
                msg,
            )

        commit("initial")
        (fixture / "notes.md").write_text("Release notes\n")
        commit("doc update")

        assert result("repo-inventory", fixture)["status"] == "ok"
        assert (
            result("tools", "describe", "repo-inventory")["definitions"][0]["command"]
            == "repo-inventory"
        )
        cfg.write_text('[plugins]\ndisabled=["appsec-analyzer","repo-inventory"]\n')
        run(cli, "repo-inventory", fixture, codes=(2,))

        def score(*options, codes=(0,)):
            return result("security-score", fixture, *options, codes=codes)

        # Only the engine version of the historic release matters here.
        assert score(codes=(0, 1, 3))["run"]["tool_version"] == "0.3.2"
        for wheel in args.release.glob("*.whl"):
            shutil.copy(wheel, index)
        update = result("update", "--yes")
        assert update["before"]["version"] == "0.0.9", update
        assert update["after"]["version"] == "0.1.0", update
        assert update["after"]["tools"]["security-score"] == "0.1.0", update
        assert "appsec-verifier" in update["after"]["tools"], update
        assert "team-report" not in update["after"]["tools"], update
        assert run(cli, "--version").splitlines()[0] == "appsec-cli 0.1.0"
        upgraded = score()
        assert upgraded["run"]["tool_version"] == "0.3.3", upgraded
        assert upgraded["status"] == "ok", upgraded
        change = score("--commit", "HEAD")
        assert "relevance" in change["data"], change
        statuses = {
            t["name"]: t["status"]
            for t in result("tools", "list", "--all", "--check")["tools"]
        }
        assert (
            statuses["appsec-analyzer"] == "disabled"
            and statuses["appsec-verifier"] == "ready"
        )
        assert "team-report" not in statuses
        run(cli, "appsec-analyzer", "--help", codes=(2,))
        run(cli, "team-report", "sample", codes=(2,))

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
            work / "team-findings/tests",
        )
        cfg.write_text('[plugins]\nadditional=["team-group","team-findings"]\n')
        assert result("team-group", "summary", "example")["data"]["characters"] == 7
        assert (
            result("--fail-on", "info", "team-findings", "TODO", codes=(1,))["counts"][
                "info"
            ]
            == 1
        )
        assert result("appsec-analyzer", "repo-profile", fixture)["status"] == "ok"
        assert all(
            t["status"] == "ready" for t in result("tools", "list", "--check")["tools"]
        )
        print(
            "pipx install, upgrade, engine update, discovery, deactivation and standalone plugins passed."
        )


if __name__ == "__main__":
    main()
