"""Create independent PEP 517 plugin packages, without modifying the suite."""

import re
from pathlib import Path
from .config import NAME
from .sdk import ToolError


def create(name, directory, scenario, engine=None, binary=None):
    if not NAME.fullmatch(name) or name in {"schema", "tools"} or len(name) > 64:
        raise ToolError(
            "invalid_name",
            "Use a lowercase, hyphen-separated plugin name (max. 64 characters).",
        )
    if scenario == "external":
        if (
            not engine
            or not re.fullmatch(
                r"[a-zA-Z0-9][a-zA-Z0-9._-]*==[0-9]+(?:\.[0-9]+)+(?:[a-z0-9.]+)?",
                engine,
            )
            or not binary
            or not NAME.fullmatch(binary)
        ):
            raise ToolError(
                "invalid_engine",
                "Use --engine PACKAGE==VERSION and --binary COMMAND for an external wrapper.",
            )
    elif engine or binary:
        raise ToolError(
            "invalid_engine", "Engine options require the external scenario."
        )
    dependency = f', "{engine}"' if engine else ""
    target = Path(directory) / name
    try:
        target.mkdir(mode=0o755)
    except FileExistsError:
        raise ToolError("already_exists", "The destination already exists.") from None
    module = "appsec_plugin_" + name.replace("-", "_")
    source = target / "src" / module
    source.mkdir(parents=True)
    entry = name + (".summary" if scenario == "group" else "")
    project = f'''[build-system]
requires = ["setuptools>=77"]
build-backend = "setuptools.build_meta"

[project]
name = "appsec-plugin-{name}"
version = "0.1.0"
description = "Report for {name}."
requires-python = ">=3.10"
dependencies = ["appsec-cli-core>=0.1,<0.2"{dependency}]

[project.entry-points."appsec_cli.tools"]
"{entry}" = "{module}:run"

[tool.setuptools.packages.find]
where = ["src"]
'''
    (target / "pyproject.toml").write_text(project)
    body = '''from appsec_cli import Result, command
from pydantic import BaseModel


class Report(BaseModel):
    subject: str


@command(data=Report)
def run(subject: str) -> Result:
    """Report on the selected subject."""
    return Result(summary="Report complete.", data=Report(subject=subject).model_dump())
'''
    if scenario == "findings":
        body = f'''from appsec_cli import Finding, Result, command


@command(findings=True)
def run(text: str) -> Result:
    """Check the supplied text for an unresolved TODO."""
    findings = []
    if "TODO" in text:
        findings.append(Finding(rule="{name}/todo", title="Unresolved TODO", severity="info"))
    return Result(summary=f"{{len(findings)}} finding(s).", findings=findings)
'''
    if scenario == "external":
        body = f'''from pathlib import Path

from appsec_cli import Result, command
from appsec_cli.external import ExternalTool
from pydantic import JsonValue

tool = ExternalTool("{binary}")

@command(data=dict[str, JsonValue], engine_distribution="{engine.split("==")[0]}")
def run(repository: Path) -> Result:
    """Summarize a repository with the installed engine."""
    payload = tool.json([str(repository.resolve()), "--json"])
    return Result(summary="Engine completed.", data=payload)
'''
    (source / "__init__.py").write_text(body)
    test_dir = target / "tests"
    test_dir.mkdir()
    assertion = 'self.assertEqual(result.data, {"subject": "example"})'
    if scenario == "findings":
        assertion = 'self.assertEqual(run.handler("TODO").findings[0].severity, "info")'
    (test_dir / "test_plugin.py").write_text(
        f"import unittest\nfrom {module} import run\n\n\n"
        "class PluginContract(unittest.TestCase):\n"
        "    def test_report(self):\n"
        '        result = run.handler("example")\n'
        '        self.assertEqual(result.status, "ok")\n'
        f"        {assertion}\n"
    )
    if scenario == "external":
        (test_dir / "test_plugin.py").write_text(
            "from pathlib import Path\nimport unittest\nfrom unittest.mock import patch\n"
            f"from {module} import run, tool\n\n"
            "class PluginContract(unittest.TestCase):\n"
            "    def test_engine_mapping(self):\n"
            '        with patch.object(tool, "json", return_value={"count": 3}) as engine:\n'
            '            self.assertEqual(run.handler(Path(".")).data, {"count": 3})\n'
            '            engine.assert_called_once_with([str(Path(".").resolve()), "--json"])\n'
        )
    (target / "README.md").write_text(
        f"# {name}\n\nBuild with `python -m build --wheel`. "
        f"Install the wheel with `pipx inject appsec-cli dist/<wheel>.whl`. "
        f"Add `{name}` to `[plugins].additional` in the user configuration.\n\n"
        f"Try `appsec-cli {entry.replace('.', ' ')} --help`. "
        "Publish the wheel in your team index and increment its version for each release.\n"
    )
    return {
        "package": "appsec-plugin-" + name,
        "directory": str(target),
        "command": entry.replace(".", " "),
    }
