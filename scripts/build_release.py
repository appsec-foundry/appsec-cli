"""Build the suite wheel set from this checkout and the pinned upstream commits."""

import hashlib
from argparse import ArgumentParser
from pathlib import Path
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
SOURCES = (
    ("score", "1c5a9b21d570c7c5650f80de3c7a1fdd43932d82", "security-score"),
    ("analyzer", "165425abccc7ca9b3dddb04c8f7a080293b0023e", "."),
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
        "--score", type=Path, required=True, help="Trusted appsec-tools Git checkout"
    )
    p.add_argument(
        "--analyzer",
        type=Path,
        required=True,
        help="Trusted appsec-analyzer Git checkout",
    )
    p.add_argument("--out", type=Path, default=ROOT / "dist")
    args = p.parse_args()
    target = args.out.resolve()
    target.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="appsec-build-") as tmp:
        for name, commit, folder in SOURCES:
            checkout = Path(tmp, name)
            subprocess.run(
                [
                    "git",
                    "-c",
                    "core.hooksPath=/dev/null",
                    "clone",
                    "--no-local",
                    "--no-checkout",
                    str(getattr(args, name).resolve()),
                    str(checkout),
                ],
                check=True,
            )
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(checkout),
                    "-c",
                    "core.hooksPath=/dev/null",
                    "checkout",
                    "--detach",
                    commit,
                ],
                check=True,
            )
            build(checkout / folder, target)
    for project in [
        ROOT / "core",
        *sorted((ROOT / "plugins").glob("*/pyproject.toml")),
        ROOT,
    ]:
        build(project.parent if project.is_file() else project, target)
    # An index may contain multiple releases. Freeze only this build's outputs.
    names = [
        "appsec_cli",
        "appsec_cli_core",
        "appsec_analyzer",
        "appsec_security_score",
        *(
            "appsec_plugin_" + p.name.replace("-", "_")
            for p in (ROOT / "plugins").iterdir()
            if (p / "pyproject.toml").is_file()
        ),
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
