"""Test plugins for the core tests, so that they need none of the shipped tools.

install() writes two plugin distributions and a JSON engine into a temporary
directory and puts it on sys.path. The CLI finds them through their metadata,
as it finds any installed plugin; CONFIG enables them under [plugins].additional.
"""

import importlib
import sys
import tempfile
from pathlib import Path

CONFIG = '[plugins]\nadditional = ["fixture", "fixture-group"]\n'

# The summaries and examples a suite build would collect for the two tools.
USAGE = {
    "fixture": {
        "examples": [{"run": "fixture .", "what": "Scan the current repository"}]
    },
    "fixture-group": {
        "commands": {
            "export": {
                "summary": "Export a saved report.",
                "examples": [
                    {"run": "fixture-group export report.json", "what": "Export it"}
                ],
            },
            "show": {"summary": "Show one entry of a report."},
        }
    },
}

ENGINE = """#!{python}
import argparse
import json
import sys

parser = argparse.ArgumentParser(prog="fixture-engine", description="Test engine.")
parser.add_argument("paths", nargs="*", help="What to scan.")
parser.add_argument("--checks", help="Run only these checks.")
parser.add_argument("--finding", action="store_true", help="Report one finding.")
parser.add_argument("--fail", action="store_true", help="Stop without a result.")
parser.add_argument("--partial", action="store_true", help="Leave out some source.")
options = parser.parse_args()
if options.fail:
    sys.exit("Reading sources...\\nThe repository does not exist.")
print(json.dumps({"args": sys.argv[1:], "findings": int(options.finding)}))
"""

# A wrapper: everything after the tool name goes to the engine.
SCAN = '''from pathlib import Path

import typer
from appsec_cli import Finding, Result, ToolError, command
from appsec_cli.external import check_usage, invoke, json_object, last_line

ENGINE = str(Path(__file__).resolve().parents[1] / "fixture-engine")


@command(
    findings=True,
    forward_except=("--update", "--analyzer", "--token-env"),
    engine_help=("fixture-engine", "--help"),
)
def scan(ctx: typer.Context) -> Result:
    """Scan with the fixture engine."""
    stderr = bytearray()
    code, raw = invoke([ENGINE, *ctx.args], stderr=stderr)
    check_usage(code, raw, stderr)
    if code:
        raise ToolError("scan_failed", last_line(stderr) or "The scan failed.")
    data = json_object(raw)
    found = [Finding(rule="fixture/check", title="Fixture finding", severity="high")]
    return Result(
        status="partial" if "--partial" in ctx.args else "ok",
        summary="Scanned.",
        data=data,
        findings=found[: data["findings"]],
    )
'''

# A tool with several typed commands.
GROUP = '''from appsec_cli import Result, command


@command()
def export(report: str, output: str = "-") -> Result:
    """Export a saved report."""
    return Result(summary=f"Exported {report}.")


@command()
def show(name: str) -> Result:
    """Show one entry of a report."""
    return Result(summary=f"Showed {name}.")
'''

DISTRIBUTIONS = {
    "fixture": ("Scan with the fixture engine.", SCAN, {"fixture": "scan"}),
    "fixture-group": (
        "Export and show saved reports.",
        GROUP,
        {"fixture-group.export": "export", "fixture-group.show": "show"},
    ),
}

_root = None


def install():
    """The directory with the test plugins, written once per test process."""
    global _root
    if _root is None:
        _root = tempfile.TemporaryDirectory(prefix="appsec-fixture-")
        root = Path(_root.name)
        engine = root / "fixture-engine"
        engine.write_text(ENGINE.replace("{python}", sys.executable))
        engine.chmod(0o700)
        for name, (summary, source, entries) in DISTRIBUTIONS.items():
            module = "appsec_plugin_" + name.replace("-", "_")
            (root / module).mkdir()
            (root / module / "__init__.py").write_text(source)
            info = root / f"{module}-0.1.0.dist-info"
            info.mkdir()
            (info / "METADATA").write_text(
                "Metadata-Version: 2.1\n"
                f"Name: appsec-plugin-{name}\nVersion: 0.1.0\nSummary: {summary}\n"
            )
            (info / "entry_points.txt").write_text(
                "[appsec_cli.tools]\n"
                + "".join(f"{e} = {module}:{f}\n" for e, f in entries.items())
            )
        sys.path.insert(0, str(root))
        importlib.invalidate_caches()
    return Path(_root.name)


def engine(real):
    """engine() of the CLI that also knows the fixture engine."""
    return lambda name: (
        str(install() / "fixture-engine") if name == "fixture-engine" else real(name)
    )
