"""Build the suite wheel set from this checkout and the engine sources of its tools."""

import hashlib
import importlib.util
from argparse import ArgumentParser
from dataclasses import replace
from pathlib import Path
import subprocess
import sys
import tempfile

try:
    import tomllib
except ImportError:  # Python 3.10
    import tomli as tomllib

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location(
    "manifests", ROOT / "core/src/appsec_cli/manifests.py"
)
manifests = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(manifests)


def adapters(root=ROOT):
    """Tool directories that hold their own Python package."""
    return sorted(
        path.parent
        for path in (root / "tools").glob("*/pyproject.toml")
        if not path.parent.name.startswith(("_", "."))
    )


def declared(folder):
    """The engine source a tool directory names, or None."""
    if (folder / "tool.toml").is_file():
        return manifests.Manifest.read(folder / "tool.toml").source
    if not (folder / "pyproject.toml").is_file():
        return None
    doc = tomllib.loads((folder / "pyproject.toml").read_text())
    table = doc.get("tool", {}).get("appsec-cli", {}).get("source")
    if table is None:
        return None
    spec = manifests.source(table, folder.name)
    pinned = {
        canonicalize_name(req.name)
        for req in map(Requirement, doc["project"].get("dependencies", []))
        if [pin.operator for pin in req.specifier] == ["=="]
    }
    if spec.package not in pinned:
        raise ValueError(f"{folder.name}: pin {spec.package} with == in dependencies")
    return spec


def sources(root=ROOT, overrides=()):
    """The engines the tool directories build from Git, by package name.

    overrides holds PACKAGE=URL pairs that build an engine from another Git URL,
    such as an internal mirror, or from a local checkout. The commit stays.
    """
    found = {}
    for folder in sorted((root / "tools").iterdir()):
        if not folder.is_dir() or folder.name.startswith(("_", ".")):
            continue
        try:
            spec = declared(folder)
        except ValueError as error:
            raise SystemExit(f"tools/{error}") from None
        if spec is not None and found.setdefault(spec.package, spec) != spec:
            raise SystemExit(
                f"tools/{folder.name}: another tool names a different source"
                f" for {spec.package}."
            )
    for pair in overrides:
        package, _, url = pair.partition("=")
        key = canonicalize_name(package)
        if key not in found or not url:
            raise SystemExit(f"--source {pair}: no tool builds {package} from Git.")
        found[key] = replace(found[key], git=url)
    return found


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
            "--",
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
        "--source",
        action="append",
        default=[],
        metavar="PACKAGE=URL",
        help="Build an engine from another trusted Git URL or checkout",
    )
    p.add_argument("--out", type=Path, default=ROOT / "dist")
    p.add_argument(
        "--release",
        action="store_true",
        help="Also stop when a version would not reach the teams (make release-check)",
    )
    args = p.parse_args()
    engines = sources(overrides=args.source)
    if args.release:
        check_versions()
    target = args.out.resolve()
    target.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="appsec-build-") as tmp:
        for number, spec in enumerate(engines.values()):
            checkout(spec.git, spec.commit, Path(tmp, str(number)))
            build(Path(tmp, str(number), spec.path), target)
    for project in [ROOT / "core", *adapters(), ROOT]:
        build(project, target)
    # An index may contain multiple releases. Freeze only this build's outputs.
    names = [
        "appsec_cli",
        "appsec_cli_core",
        *(package.replace("-", "_") for package in engines),
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
