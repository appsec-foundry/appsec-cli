"""Console entry point. Only the selected entry point is imported."""

import argparse
import os
import sys
import time
from datetime import datetime, timezone
from importlib.metadata import version

import click
import typer
from typer.main import get_command

from . import ui
from .catalog import discover
from .config import settings, threshold
from .output import emit, finalize, sarif
from .scaffold import create
from .sdk import Envelope, Result, SEVERITIES, ToolError


def parser():
    p = argparse.ArgumentParser(prog="appsec-cli", add_help=False, allow_abbrev=False)
    p.add_argument("--help", "-h", action="store_true")
    p.add_argument("--version", action="store_true")
    p.add_argument("--format", choices=("table", "json", "sarif"), default="table")
    p.add_argument("--fail-on", choices=(*SEVERITIES, "never"))
    p.add_argument("--min-severity", choices=SEVERITIES, default="info")
    p.add_argument("--limit", type=int)
    p.add_argument("--output")
    p.add_argument("--config")
    p.add_argument("--debug", action="store_true")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("-q", "--quiet", action="store_true")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("args", nargs=argparse.REMAINDER)
    return p


def as_command(spec):
    app = typer.Typer(
        add_completion=False, rich_markup_mode=None, pretty_exceptions_enable=False
    )
    app.command()(spec.handler)
    return get_command(app)


def select(tools, name):
    if name not in tools:
        raise click.UsageError("Unknown tool. See 'appsec-cli tools list'.")
    tool = tools[name]
    if tool.status == "disabled":
        raise click.UsageError(
            f"tool_disabled: {name}. See 'appsec-cli tools list --all'."
        )
    return tool


def describe(tool):
    if tool.status != "unchecked":
        raise ToolError("tool_" + tool.status, f"{tool.name} is {tool.status}.")
    details = tool.description()
    definitions = []
    for name in sorted(tool.commands):
        spec = tool.load(name)
        cmd = as_command(spec)
        with click.Context(cmd) as ctx:
            definitions.append(
                {
                    "command": " ".join(filter(None, (tool.name, name))),
                    "help": cmd.help,
                    "parameters": [
                        {
                            "name": p.name,
                            "options": p.opts,
                            "required": p.required,
                            "type": p.type.name,
                            "help": getattr(p, "help", ""),
                        }
                        for p in cmd.get_params(ctx)
                    ],
                    "data_schema": spec.data_adapter.json_schema(),
                    "formats": ["table", "json"] + (["sarif"] if spec.findings else []),
                }
            )
    return {"schema_version": 1, **details, "definitions": definitions}


def manage(args, tools, args0):
    p = argparse.ArgumentParser(prog="appsec-cli tools")
    sub = p.add_subparsers(dest="operation")
    listing = sub.add_parser("list", help="List installed commands")
    listing.add_argument("--all", action="store_true")
    listing.add_argument("--check", action="store_true")
    info = sub.add_parser("describe", help="Show arguments, formats and data schema")
    info.add_argument("name")
    new = sub.add_parser("new", help="Create a standalone plugin project")
    new.add_argument("name")
    new.add_argument("--directory", default=".")
    new.add_argument(
        "--scenario", choices=["data", "findings", "group", "external"], default="data"
    )
    new.add_argument(
        "--engine",
        metavar="PACKAGE==VERSION",
        help="Pinned distribution providing an external CLI",
    )
    new.add_argument(
        "--binary", metavar="COMMAND", help="Console script provided by the engine"
    )
    opts = p.parse_args(args or ["list"])
    if opts.operation == "new":
        item = create(
            opts.name, opts.directory, opts.scenario, opts.engine, opts.binary
        )
        return (
            item
            if args0.format == "json"
            else f"Created {item['package']} in {item['directory']}"
        )
    if opts.operation == "describe":
        result = describe(select(tools, opts.name))
        if args0.format == "json":
            return result
        lines = [ui.clean(result["help"])]
        for cmd in result["definitions"]:
            lines.extend(["", cmd["command"], ui.clean(cmd["help"] or "")])
            for option in cmd["parameters"]:
                lines.append(
                    "  "
                    + ", ".join(option["options"])
                    + "  "
                    + ui.clean(option["help"] or "")
                )
        return "\n".join(lines)
    rows = []
    for tool in tools.values():
        if tool.status == "disabled" and not opts.all:
            continue
        row = tool.description()
        if opts.check and tool.status == "unchecked":
            try:
                describe(tool)
                row["status"] = "ready"
            except ToolError as e:
                row["status"] = e.code
        rows.append(row)
    return (
        {"schema_version": 1, "tools": rows}
        if args0.format == "json"
        else ui.overview(rows, args0.no_color, full=True)
    )


def execute(opts):
    if opts.version:
        emit(version("appsec-cli"))
        return 0
    cfg = settings(opts.config)
    tools = discover(cfg)
    args = list(opts.args)
    if not args or opts.help:
        rows = [
            tool.description() for tool in tools.values() if tool.status != "disabled"
        ]
        value = ui.overview(rows, opts.no_color)
        if opts.help:
            value += "\n\n" + parser().format_help()
        emit(
            {"schema_version": 1, "tools": rows} if opts.format == "json" else value,
            opts.output,
        )
        return 0
    name = args.pop(0)
    if name in {"tools", "schema"}:
        if opts.format == "sarif":
            raise click.UsageError("SARIF is available for finding-producing commands.")
        if name == "schema" and args:
            raise click.UsageError("Usage: appsec-cli schema")
        emit(
            manage(args, tools, opts)
            if name == "tools"
            else Envelope.model_json_schema(),
            opts.output,
        )
        return 0
    tool = select(tools, name)
    if tool.status != "unchecked":
        raise ToolError("tool_" + tool.status, f"{name} is {tool.status}.")
    subcommand = ""
    if "" not in tool.commands:
        if not args or args[0] in ("--help", "-h"):
            emit(
                "Usage: appsec-cli "
                + name
                + " COMMAND [ARGS]\n\n"
                + "\n".join("  " + path for path in tool.description()["commands"])
            )
            return 0
        subcommand = args.pop(0)
        if subcommand not in tool.commands:
            raise click.UsageError(f"Unknown subcommand for {name}.")
    spec = tool.load(subcommand)
    if opts.format == "sarif" and not spec.findings:
        raise click.UsageError("This command publishes data. Use --format json.")
    fail = (
        opts.fail_on
        or os.getenv("APPSEC_CLI_FAIL_ON")
        or cfg.thresholds.get(name)
        or cfg.fail_on
        or spec.fail_on
        or "low"
    )
    fail = threshold(fail)
    start = time.monotonic()
    started = datetime.now(timezone.utc).isoformat()
    if opts.verbose and not opts.quiet:
        print(f"Running {name}", file=sys.stderr)
    cmd = as_command(spec)
    result = cmd.main(
        args=args,
        prog_name=" ".join(filter(None, ("appsec-cli", name, subcommand))),
        standalone_mode=False,
        color=False,
    )
    if result == 0:  # Click help
        return 0
    if not isinstance(result, Result):
        raise ToolError("invalid_result", "The plugin returned an invalid result.")
    run = {
        "cli_version": version("appsec-cli"),
        "tool_version": version(spec.engine_distribution)
        if spec.engine_distribution
        else tool.version,
        "plugin_version": tool.version,
        "started_at": started,
        "duration_ms": int((time.monotonic() - start) * 1000),
    }
    report, code = finalize(
        result, name, spec, run, fail, opts.min_severity, opts.limit
    )
    value = {
        "json": lambda: report,
        "table": lambda: ui.table(
            report, opts.no_color or bool(opts.output), spec.render_data
        ),
        "sarif": lambda: sarif(report, result.findings or []),
    }[opts.format]()
    emit(value, opts.output)
    return code


def main(argv=None):
    opts = parser().parse_args(argv)
    if opts.limit is not None and opts.limit < 0:
        parser().error("--limit must be non-negative")
    try:
        return execute(opts)
    except click.ClickException as exc:
        print("Error:", ui.clean(exc.format_message()), file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130
    except Exception as exc:
        known = isinstance(exc, ToolError)
        code = exc.code if known else "internal_error"
        msg = str(exc) if known else "The command did not produce a valid result."
        if opts.debug:
            print(type(exc).__name__, file=sys.stderr)
        name = (
            opts.args[0]
            if opts.args and opts.args[0].isascii() and opts.args[0].isidentifier()
            else "appsec-cli"
        )
        if opts.args and opts.args[0].replace("-", "").isalnum():
            name = opts.args[0]
        result = {
            "schema_version": 1,
            "tool": name,
            "status": "failed",
            "summary": msg,
            "diagnostics": [{"level": "error", "code": code, "message": msg}],
        }
        value = (
            sarif(result)
            if opts.format == "sarif"
            else result
            if opts.format == "json"
            else ui.table(result, opts.no_color)
        )
        try:
            emit(value, opts.output)
        except ToolError:
            print("Error: could not write output.", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
