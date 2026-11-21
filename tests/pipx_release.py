"""Exercise a real pipx upgrade against a temporary, exclusively local package index."""

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HISTORIC_SCORE = "0294a9338caaf17d531bb222e86c353b81d60828"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--wheels", type=Path, required=True, help="External dependency wheels"
    )
    parser.add_argument(
        "--score", type=Path, required=True, help="Trusted appsec-tools checkout"
    )
    parser.add_argument("--release", type=Path, default=ROOT / "dist")
    args = parser.parse_args()
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
            args.score.resolve(),
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
        old = work / "old-plugin"
        shutil.copytree(
            ROOT / "plugins/security-score/src",
            old / "src",
            ignore=shutil.ignore_patterns("*.egg-info", "__pycache__"),
        )
        (old / "pyproject.toml").write_text(
            (ROOT / "plugins/security-score/pyproject.toml")
            .read_text()
            .replace('version = "0.1.0"', 'version = "0.0.9"')
            .replace("score==0.3.3", "score==0.3.2")
        )
        build(old)

        old_suite = work / "old-suite"
        shutil.copytree(ROOT / "src/appsec_suite", old_suite / "src/appsec_suite")
        shutil.copytree(ROOT / "skills", old_suite / "skills")
        shutil.copy(ROOT / "setup.py", old_suite)
        shutil.copytree(ROOT / "modules", old_suite / "modules")
        # A team module consists exclusively of this single TOML file.
        local_module = old_suite / "modules" / "repo-inventory"
        local_module.mkdir()
        (local_module / "tool.toml").write_text(
            'engine = "appsec-analyzer==0.1.0a0"\nargs = ["repo-profile", "{repo}", "--json"]\n'
        )
        manifest = (
            (ROOT / "pyproject.toml")
            .read_text()
            .replace('version = "0.1.0"', 'version = "0.0.9"')
            .replace("security-score==0.1.0", "security-score==0.0.9")
        )
        manifest = manifest.replace(
            "appsec-plugin-appsec-verifier==0.1.0", "appsec-plugin-team-report==0.1.0"
        ).replace(
            'appsec-verifier = "appsec_plugin_appsec_verifier"',
            'team-report = "appsec_plugin_team_report"',
        )
        (old_suite / "pyproject.toml").write_text(manifest)

        # Generate the team plugin with the release's own scaffold.
        sys.path.insert(0, str(ROOT / "core/src"))
        from appsec_cli.scaffold import create

        create("team-report", work, "data")
        build(work / "team-report")
        build(old_suite)
        run("pipx", "install", "appsec-cli")
        cli = work / "bin/appsec-cli"

        def result(*args, codes=(0,)):
            return json.loads(run(cli, "--format", "json", *args, codes=codes))

        assert result("team-report", "sample")["data"] == {"subject": "sample"}
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
        run("pipx", "upgrade", "appsec-cli")
        assert run(cli, "--version").strip() == "0.1.0"
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

        result(
            "tools",
            "new",
            "team-wrapper",
            "--scenario",
            "external",
            "--engine",
            "appsec-security-score==0.3.3",
            "--binary",
            "security-score",
        )
        build(work / "team-wrapper")
        run("pipx", "inject", "appsec-cli", "appsec-plugin-team-wrapper")
        wrapper_python = work / "pipx/venvs/appsec-cli/bin/python"
        run(
            wrapper_python,
            "-m",
            "unittest",
            "discover",
            "-s",
            work / "team-wrapper/tests",
        )
        for name, mode in [("team-findings", "findings"), ("team-group", "group")]:
            result("tools", "new", name, "--scenario", mode)
            build(work / name)
            run("pipx", "inject", "appsec-cli", "appsec-plugin-" + name)
        cfg.write_text('[plugins]\nadditional=["team-group","team-findings"]\n')
        assert (
            result("team-group", "summary", "example")["data"]["subject"] == "example"
        )
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
