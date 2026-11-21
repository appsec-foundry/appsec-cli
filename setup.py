"""Include engines declared by modules in the normal pip / pipx installation."""

import sys
from pathlib import Path
from setuptools import setup

root = Path(__file__).resolve().parent
sys.path.insert(0, str(root / "src"))
from appsec_suite.manifests import Manifest, tomllib  # noqa: E402

with (root / "pyproject.toml").open("rb") as stream:
    project = tomllib.load(stream)
dependencies = project["tool"]["appsec-suite"]["dependencies"]
reserved = project["tool"]["appsec-suite"]["bundle"]
entries = {
    "console_scripts": ["appsec-cli = appsec_cli.cli:main"],
    "appsec_cli.bundle": [f"{key} = {value}" for key, value in reserved.items()],
    "appsec_cli.manifests": [],
}
for path in sorted((root / "modules").glob("*/tool.toml")):
    module = Manifest.read(path)
    if module.name in reserved:
        raise ValueError(f"{module.name}: module collides with a bundled plugin")
    dependencies.append(str(module.engine))
    entries["appsec_cli.manifests"].append(f"{module.name} = appsec_suite.modules")
setup(install_requires=list(dict.fromkeys(dependencies)), entry_points=entries)
