"""Build the suite wheel set from this checkout and the pinned upstream commits."""

import hashlib
from argparse import ArgumentParser
from pathlib import Path
import subprocess
import sys
import tempfile

try:
    import tomllib
except ImportError:  # Python 3.10
    import tomli as tomllib


ROOT = Path(__file__).resolve().parents[1]
SOURCES = (
    ("score", "1c5a9b21d570c7c5650f80de3c7a1fdd43932d82", "security-score"),
    ("analyzer", "165425abccc7ca9b3dddb04c8f7a080293b0023e", "."),
)


def adapters(root=ROOT):
    """Tool directories that hold their own Python package."""
    return sorted(
        path.parent
        for path in (root / "tools").glob("*/pyproject.toml")
        if not path.parent.name.startswith(("_", "."))
    )


def git(root, *args):
    run = subprocess.run(
        ["git", "-C", str(root), *args], capture_output=True, text=True
    )
    return run.returncode, run.stdout.strip()


def project_version(text):
    return tomllib.loads(text)["project"]["version"]


def check_versions(root=ROOT):
    """Stop a release whose versions would not reach the teams.

    The suite version must not be released yet, and a package that changed since
    the last release needs a new version; otherwise pip keeps the old one.
    """
    suite = project_version((root / "pyproject.toml").read_text())
    code, released = git(root, "rev-parse", "-q", "--verify", f"v{suite}^{{commit}}")
    if code == 0 and released != git(root, "rev-parse", "HEAD")[1]:
        raise SystemExit(
            f"v{suite} is already released; raise the version in pyproject.toml."
        )
    _, tags = git(root, "tag", "--list", "v*", "--sort=-v:refname")
    last = next((tag for tag in tags.splitlines() if tag != f"v{suite}"), None)
    if last is None:
        return
    stale = []
    for folder in [root / "core", *adapters(root)]:
        path = folder.relative_to(root).as_posix()
        changed = git(root, "diff", "--quiet", last, "--", path)[0] == 1
        code, old = git(root, "show", f"{last}:{path}/pyproject.toml")
        current = project_version((folder / "pyproject.toml").read_text())
        if changed and code == 0 and project_version(old) == current:
            stale.append(path)
    if stale:
        raise SystemExit(
            f"Changed since {last} without a new version: {', '.join(stale)}."
        )


def checkout(source, commit, target):
    """Clone a Git URL or local repository and check out the pinned commit."""
    subprocess.run(
        [
            "git",
            "-c",
            "core.hooksPath=/dev/null",
            "clone",
            "--no-local",
            "--no-checkout",
            source,
            str(target),
        ],
        check=True,
    )
    subprocess.run(
        [
            "git",
            "-C",
            str(target),
            "-c",
            "core.hooksPath=/dev/null",
            "checkout",
            "--detach",
            commit,
        ],
        check=True,
    )


def build(project, target):
    subprocess.run(
        [
            sys.executable,
            "-m",
            "pip",
            "wheel",
            "--no-index",
            "--no-build-isolation",
            "--no-deps",
            "--wheel-dir",
            str(target),
            str(project),
        ],
        check=True,
    )


def main():
    p = ArgumentParser(description=__doc__)
    p.add_argument(
        "--score", required=True, help="Trusted appsec-tools Git URL or checkout"
    )
    p.add_argument(
        "--analyzer",
        required=True,
        help="Trusted appsec-analyzer Git URL or checkout",
    )
    p.add_argument("--out", type=Path, default=ROOT / "dist")
    p.add_argument(
        "--release",
        action="store_true",
        help="Also stop when a version would not reach the teams (make release-check)",
    )
    args = p.parse_args()
    if args.release:
        check_versions()
    target = args.out.resolve()
    target.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="appsec-build-") as tmp:
        for name, commit, folder in SOURCES:
            checkout(getattr(args, name), commit, Path(tmp, name))
            build(Path(tmp, name, folder), target)
    for project in [ROOT / "core", *adapters(), ROOT]:
        build(project, target)
    # An index may contain multiple releases. Freeze only this build's outputs.
    names = [
        "appsec_cli",
        "appsec_cli_core",
        "appsec_analyzer",
        "appsec_security_score",
        *("appsec_plugin_" + p.name.replace("-", "_") for p in adapters()),
    ]
    wheels = [w for w in target.glob("*.whl") if w.name.split("-")[0] in names]
    if len(wheels) != len(names):
        raise SystemExit(
            "Use a dedicated release directory containing one wheel per package."
        )
    rows = []
    for wheel in sorted(wheels):
        digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
        name, version = wheel.name.split("-")[:2]
        rows.append(f"{name}=={version} --hash=sha256:{digest}")
    (target / "release.lock").write_text("\n".join(rows) + "\n")


if __name__ == "__main__":
    main()
