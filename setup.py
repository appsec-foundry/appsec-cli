"""Build the suite: every directory in tools/ is one command of the release.

A directory with tool.toml wraps a JSON engine; one with pyproject.toml is a
Python adapter that is built as its own wheel and pinned here. Directories whose
name starts with an underscore, such as tools/_template, are not part of it.
A tool with enabled = false is shipped, but stays off until a team enables it.
"""

import importlib.util
import json
from pathlib import Path

from packaging.requirements import Requirement
from setuptools import setup
from setuptools.command.build_py import build_py

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


def load(path):
    with path.open("rb") as stream:
        return tomllib.load(stream)


core = load(ROOT / "core/pyproject.toml")["project"]
dependencies = [f"{core['name']}=={core['version']}"]
entries = {
    "console_scripts": ["appsec-cli = appsec_cli.cli:main"],
    "appsec_cli.bundle": [],
    "appsec_cli.manifests": [],
    "appsec_cli.optional": [],
}
usage = {}
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
        manifest = manifests.Manifest.read(wrapper)
        dependencies.append(str(manifest.engine))
        entries["appsec_cli.manifests"].append(f"{name} = appsec_suite.tools")
        if not manifest.enabled:
            entries["appsec_cli.optional"].append(f"{name} = appsec_suite.tools")
        continue
    doc = load(adapter)
    package = doc["project"]
    if package["name"] != f"appsec-plugin-{name}":
        raise ValueError(f"tools/{name}: name the package appsec-plugin-{name}")
    dependencies.append(f"{package['name']}=={package['version']}")
    module = "appsec_plugin_" + name.replace("-", "_")
    entries["appsec_cli.bundle"].append(f"{name} = {module}")
    table = doc.get("tool", {}).get("appsec-cli", {})
    if not isinstance(table, dict):
        raise ValueError(f"tools/{name}: [tool.appsec-cli] is a table")
    if not manifests.enabled(table.get("enabled", True), name):
        entries["appsec_cli.optional"].append(f"{name} = {module}")
    engine = table.get("engine")
    pins = {
        r.name
        for r in map(Requirement, package.get("dependencies", []))
        if [s.operator for s in r.specifier] == ["=="]
    }
    if engine is not None and engine not in pins:
        raise ValueError(f"tools/{name}: engine names a dependency pinned with ==")
    # scripts/build_release.py reads the source; the CLI needs the usage and engine.
    table = {k: v for k, v in table.items() if k not in ("enabled", "source", "engine")}
    if table:
        commands = package.get("entry-points", {}).get("appsec_cli.tools", {})
        manifests.usage(name, table, {c.partition(".")[2] for c in commands})
    if engine is not None:
        table["engine"] = engine
    if table:
        usage[name] = table


class BuildPy(build_py):
    """Ship the summaries, examples and engines of the adapters with the suite.

    The CLI shows them on its start page, in the help and in tools list without
    importing a tool.
    """

    def run(self):
        super().run()
        target = Path(self.build_lib, "appsec_suite", "usage.json")
        target.write_text(json.dumps(usage, indent=1, sort_keys=True), "utf-8")


setup(
    install_requires=list(dict.fromkeys(dependencies)),
    entry_points=entries,
    cmdclass={"build_py": BuildPy},
)
