"""Build the suite: every directory in tools/ is one command of the release.

A directory with tool.toml wraps a JSON engine; one with pyproject.toml is a
Python adapter that is built as its own wheel and pinned here. Directories whose
name starts with an underscore, such as tools/_template, are not part of it.
"""

import importlib.util
from pathlib import Path

from setuptools import setup

try:
    import tomllib
except ImportError:  # Python 3.10
    import tomli as tomllib

ROOT = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location(
    "manifests", ROOT / "core/src/appsec_cli/manifests.py"
)
manifests = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(manifests)


def project(path):
    with path.open("rb") as stream:
        return tomllib.load(stream)["project"]


core = project(ROOT / "core/pyproject.toml")
dependencies = [f"{core['name']}=={core['version']}"]
entries = {
    "console_scripts": ["appsec-cli = appsec_cli.cli:main"],
    "appsec_cli.bundle": [],
    "appsec_cli.manifests": [],
}
for folder in sorted((ROOT / "tools").iterdir()):
    name = folder.name
    if not folder.is_dir() or name.startswith(("_", ".")):
        continue
    if not manifests.NAME.fullmatch(name) or name in manifests.RESERVED:
        raise ValueError(f"tools/{name}: use a lowercase, hyphenated command name")
    adapter, wrapper = folder / "pyproject.toml", folder / "tool.toml"
    if adapter.is_file() == wrapper.is_file():
        raise ValueError(f"tools/{name}: add either tool.toml or pyproject.toml")
    if wrapper.is_file():
        dependencies.append(str(manifests.Manifest.read(wrapper).engine))
        entries["appsec_cli.manifests"].append(f"{name} = appsec_suite.tools")
        continue
    package = project(adapter)
    if package["name"] != f"appsec-plugin-{name}":
        raise ValueError(f"tools/{name}: name the package appsec-plugin-{name}")
    dependencies.append(f"{package['name']}=={package['version']}")
    module = "appsec_plugin_" + name.replace("-", "_")
    entries["appsec_cli.bundle"].append(f"{name} = {module}")
setup(install_requires=list(dict.fromkeys(dependencies)), entry_points=entries)
