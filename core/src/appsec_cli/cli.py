"""Console entry point: one click group. A tool is imported only when selected."""

import difflib
import json
import os
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from importlib.metadata import version
from pathlib import Path

import click
import typer
from typer.main import get_command

from . import ui
from .catalog import discover
from .config import settings, threshold
from .output import emit, finalize, sarif
from .sdk import SEVERITIES, Envelope, Result, ToolError


class UsageError(click.UsageError):
    """A usage error with an optional hint for the next step."""

    def __init__(self, message, hint=None):
        super().__init__(message)
        self.hint = hint


def suggest(name, names):
    match = difflib.get_close_matches(name, names, n=1)
    return f"Did you mean '{match[0]}'?" if match else None


def options(ctx):
    return ctx.find_root().params


def style_for(ctx):
    params = options(ctx)
    return ui.Style.detect(params.get("no_color") or bool(params.get("output")))


def state(ctx):
    """Settings and tool catalog of this invocation, read once."""
    meta = ctx.find_root().meta
    if "appsec.tools" not in meta:
        meta["appsec.settings"] = settings(options(ctx).get("config"))
        meta["appsec.tools"] = discover(meta["appsec.settings"])
    return meta["appsec.settings"], meta["appsec.tools"]


def enabled_rows(ctx):
    _, tools = state(ctx)
    return [t.description() for t in tools.values() if t.status != "disabled"]


def publish(ctx, data, text):
    """Write a built-in command's result as JSON or text."""
    params = options(ctx)
    if params["format"] == "sarif":
        raise UsageError(
            "SARIF is available for commands that report findings.",
            "Use --format json.",
        )
    emit(data if params["format"] == "json" else text(), params["output"])
    return 0


def as_command(spec):
    app = typer.Typer(
        add_completion=False, rich_markup_mode=None, pretty_exceptions_enable=False
    )
    app.command()(spec.handler)
    return get_command(app)


def loaded(ctx, tool, subcommand):
    """The click command of one tool command, prepared for its run."""
    spec = tool.load(subcommand)
    if options(ctx)["format"] == "sarif" and not spec.findings:
        raise UsageError(
            "This command reports data, not findings.", "Use --format json."
        )
    ctx.meta["appsec.run"] = (tool, spec, time.monotonic(), datetime.now(timezone.utc))
    if options(ctx)["verbose"]:
        print(f"Running {tool.name}", file=sys.stderr)
    return as_command(spec)


class ToolGroup(click.Group):
    """A tool with several commands, such as appsec-analyzer export."""

    def __init__(self, tool):
        super().__init__(tool.name, help=tool.summary)
        self.tool = tool

    def list_commands(self, ctx):
        return sorted(self.tool.commands)

    def get_command(self, ctx, name):
        return loaded(ctx, self.tool, name) if name in self.tool.commands else None

    def resolve_command(self, ctx, args):
        if args[0] not in self.tool.commands:
            hint = suggest(args[0], self.list_commands(ctx))
            raise UsageError(
                f"Unknown command '{args[0]}' for {self.tool.name}.",
                hint or f"Run 'appsec-cli {self.tool.name} --help'.",
            )
        return super().resolve_command(ctx, args)


class Suite(click.Group):
    """Built-in commands plus the enabled tools of the installed suite."""

    def list_commands(self, ctx):
        return sorted(BUILTIN) + [row["name"] for row in enabled_rows(ctx)]

    def get_command(self, ctx, name):
        if name in BUILTIN:
            return BUILTIN[name]
        _, tools = state(ctx)
        tool = tools.get(name)
        if tool is None:
            return None
        if tool.status == "disabled":
            raise UsageError(
                f"Tool '{name}' is disabled.", "See 'appsec-cli tools list --all'."
            )
        ctx.meta["appsec.tool"] = name
        if tool.status != "unchecked":
            raise ToolError("tool_" + tool.status, f"{name} is {tool.status}.")
        return loaded(ctx, tool, "") if "" in tool.commands else ToolGroup(tool)

    def resolve_command(self, ctx, args):
        command = self.get_command(ctx, args[0])
        if command is None:
            hint = suggest(args[0], self.list_commands(ctx))
            raise UsageError(
                f"Unknown tool '{args[0]}'.", hint or "See 'appsec-cli tools list'."
            )
        return args[0], command, args[1:]

    def format_help(self, ctx, formatter):
        rows = [p.get_help_record(ctx) for p in self.get_params(ctx)]
        formatter.write(
            ui.overview(enabled_rows(ctx), ui.Style.detect(), version("appsec-cli"))
            + "\n\n"
            + ui.section("Global options (before the tool name)", filter(None, rows))
            + "\n"
        )


def non_negative(value):
    if value is not None and value < 0:
        raise click.BadParameter("use 0 or more.")
    return value


def show_version(ctx, param, value):
    if value and not ctx.resilient_parsing:
        lines = [f"appsec-cli {version('appsec-cli')}"]
        try:
            lines += ui.columns(
                (row["name"], row["version"]) for row in enabled_rows(ctx)
            )
        except ToolError:
            pass  # The suite version alone still helps when the settings are invalid.
        click.echo("\n".join(lines))
        ctx.exit()


@click.group(
    cls=Suite,
    invoke_without_command=True,
    context_settings={"help_option_names": ["-h", "--help"]},
)
@click.option(
    "--format",
    type=click.Choice(["table", "json", "sarif"]),
    default="table",
    metavar="FORMAT",
    help="table (default), json for automation, or sarif for findings.",
)
@click.option(
    "--output", metavar="FILE", help="Write the result to a file instead of stdout."
)
@click.option(
    "--fail-on",
    type=click.Choice([*SEVERITIES, "never"]),
    metavar="SEVERITY",
    help="Exit with 1 when a finding reaches SEVERITY (critical … info, or never).",
)
@click.option(
    "--min-severity",
    type=click.Choice(SEVERITIES),
    default="info",
    metavar="SEVERITY",
    help="Print only findings of SEVERITY or higher.",
)
@click.option(
    "--limit",
    type=int,
    metavar="N",
    callback=lambda ctx, param, value: non_negative(value),
    help="Print at most N findings.",
)
@click.option(
    "--config",
    metavar="FILE",
    help="Use this project configuration instead of .appsec-cli.toml.",
)
@click.option("--no-color", is_flag=True, help="Print text without colour.")
@click.option("-v", "--verbose", is_flag=True, help="Show diagnostic codes.")
@click.option("--debug", is_flag=True, help="Show the type of an internal error.")
@click.option(
    "--version",
    is_flag=True,
    is_eager=True,
    expose_value=False,
    callback=show_version,
    help="Show the version and exit.",
)
@click.pass_context
def cli(ctx, **params):
    if ctx.invoked_subcommand is None:
        rows = enabled_rows(ctx)
        return publish(
            ctx,
            {"schema_version": 1, "version": version("appsec-cli"), "tools": rows},
            lambda: ui.overview(rows, style_for(ctx), version("appsec-cli")),
        )


@cli.result_callback()
@click.pass_context
def finish(ctx, result, **params):
    """Turn a tool's result into the report and the exit code."""
    if "appsec.run" not in ctx.meta:
        return result or 0
    tool, spec, start, started = ctx.meta["appsec.run"]
    if not isinstance(result, Result):
        raise ToolError("invalid_result", "The plugin returned an invalid result.")
    cfg, _ = state(ctx)
    fail = threshold(
        params["fail_on"]
        or os.getenv("APPSEC_CLI_FAIL_ON")
        or cfg.thresholds.get(tool.name)
        or cfg.fail_on
        or spec.fail_on
        or "low"
    )
    run = {
        "cli_version": version("appsec-cli"),
        "tool_version": version(spec.engine_distribution)
        if spec.engine_distribution
        else tool.version,
        "plugin_version": tool.version,
        "started_at": started.isoformat(),
        "duration_ms": int((time.monotonic() - start) * 1000),
    }
    report, code = finalize(
        result, tool.name, spec, run, fail, params["min_severity"], params["limit"]
    )
    if params["format"] == "json":
        value = report
    elif params["format"] == "sarif":
        value = sarif(report, result.findings or [])
    else:
        value = ui.table(
            report,
            style_for(ctx),
            spec.render_data,
            threshold=fail,
            code=code,
            verbose=params["verbose"],
        )
    emit(value, params["output"])
    return code


@click.group("tools", invoke_without_command=True)
@click.pass_context
def tools_group(ctx):
    """List and describe the installed tools."""
    if ctx.invoked_subcommand is None:
        return ctx.invoke(tools_list)


@tools_group.command("list")
@click.option("--all", "show_all", is_flag=True, help="Include disabled tools.")
@click.option("--check", is_flag=True, help="Load every tool and report problems.")
@click.pass_context
def tools_list(ctx, show_all=False, check=False):
    """List the tools and their commands."""
    _, tools = state(ctx)
    rows = []
    for tool in tools.values():
        if tool.status == "disabled" and not show_all:
            continue
        row = tool.description()
        if check and tool.status == "unchecked":
            try:
                describe(tool)
                row["status"] = "ready"
            except ToolError as exc:
                row["status"] = exc.code
        rows.append(row)
    return publish(
        ctx,
        {"schema_version": 1, "version": version("appsec-cli"), "tools": rows},
        lambda: ui.tool_list(rows, style_for(ctx)),
    )


@tools_group.command("describe")
@click.argument("name")
@click.pass_context
def tools_describe(ctx, name):
    """Show the arguments, output formats and data schema of a tool."""
    _, tools = state(ctx)
    if name not in tools:
        hint = suggest(name, list(tools))
        raise UsageError(
            f"Unknown tool '{name}'.", hint or "See 'appsec-cli tools list'."
        )
    if tools[name].status == "disabled":
        raise UsageError(
            f"Tool '{name}' is disabled.", "See 'appsec-cli tools list --all'."
        )
    result = describe(tools[name])
    return publish(ctx, result, lambda: ui.describe(result, style_for(ctx)))


@click.command("schema")
@click.pass_context
def schema(ctx):
    """Print the JSON Schema of a result."""
    data = Envelope.model_json_schema()
    return publish(ctx, data, lambda: data)


def installed():
    """Suite and tool versions of this installation, read in a fresh process."""
    run = subprocess.run(
        [
            sys.executable,
            "-m",
            "appsec_cli",
            "--format",
            "json",
            "tools",
            "list",
            "--all",
        ],
        capture_output=True,
        text=True,
        timeout=60,
    )
    if run.returncode:
        raise ToolError("update_failed", "Cannot read the installed versions.")
    listing = json.loads(run.stdout)
    return listing["version"], {t["name"]: t["version"] for t in listing["tools"]}


@click.command("update")
@click.option("--yes", is_flag=True, help="Update without asking.")
@click.pass_context
def update(ctx, yes):
    """Update appsec-cli and its tools with pipx."""
    pipx = shutil.which("pipx")
    if not pipx or not (Path(sys.prefix) / "pipx_metadata.json").is_file():
        raise UsageError(
            "This installation is not managed by pipx.",
            "Update it the way you installed it.",
        )
    suite, tools = installed()
    if not yes:
        if options(ctx)["format"] != "table" or not sys.stdin.isatty():
            raise UsageError("Confirm the update.", "Run 'appsec-cli update --yes'.")
        if not click.confirm(f"Update appsec-cli {suite} with pipx?", default=True):
            return 0
    try:
        run = subprocess.run(
            [pipx, "upgrade", "appsec-cli"], capture_output=True, text=True, timeout=900
        )
    except subprocess.TimeoutExpired:
        raise ToolError("update_failed", "pipx did not finish in time.") from None
    if run.returncode:
        sys.stderr.write(ui.clean(run.stdout + run.stderr).strip() + "\n")
        raise ToolError("update_failed", "pipx could not update appsec-cli.")
    new_suite, new_tools = installed()
    data = {
        "schema_version": 1,
        "before": {"version": suite, "tools": tools},
        "after": {"version": new_suite, "tools": new_tools},
    }
    return publish(ctx, data, lambda: ui.changes(data, style_for(ctx)))


BUILTIN = {"schema": schema, "tools": tools_group, "update": update}


def describe(tool):
    if tool.status != "unchecked":
        raise ToolError("tool_" + tool.status, f"{tool.name} is {tool.status}.")
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
                            "default": plain(p.default),
                        }
                        for p in cmd.get_params(ctx)
                        if p.name != "help"
                    ],
                    "data_schema": spec.data_adapter.json_schema(),
                    "formats": ["table", "json"] + (["sarif"] if spec.findings else []),
                }
            )
    return {"schema_version": 1, **tool.description(), "definitions": definitions}


def plain(value):
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    return str(value)


def usage(exc):
    """Print a usage error and, where it helps, the next step."""
    message, hint = exc.format_message(), getattr(exc, "hint", None)
    root = exc.ctx.find_root() if exc.ctx else None
    if isinstance(exc, click.NoSuchOption) and root and exc.ctx is not root:
        if exc.option_name in {o for p in root.command.params for o in p.opts}:
            message = f"{exc.option_name} is a global option."
            hint = (
                f"Put it before the tool name: appsec-cli {exc.option_name} … "
                f"{exc.ctx.command_path.removeprefix('appsec-cli ')} …"
            )
    if hint is None and exc.ctx:
        hint = f"Run '{exc.ctx.command_path} --help'."
    print(f"Error: {ui.clean(message)}", file=sys.stderr)
    if hint:
        print(f"Hint: {ui.clean(hint)}", file=sys.stderr)


def failed(ctx, exc):
    """Report a run that could not produce a result; exit code 3."""
    known = isinstance(exc, ToolError)
    code = exc.code if known else "internal_error"
    message = str(exc) if known else "The command did not produce a valid result."
    params = options(ctx) if ctx else {}
    if params.get("debug"):
        print(type(exc).__name__, file=sys.stderr)
    result = {
        "schema_version": 1,
        "tool": ctx.meta.get("appsec.tool", "appsec-cli") if ctx else "appsec-cli",
        "status": "failed",
        "summary": message,
        "diagnostics": [{"level": "error", "code": code, "message": message}],
    }
    form = params.get("format", "table")
    value = (
        sarif(result)
        if form == "sarif"
        else result
        if form == "json"
        else ui.table(result, style_for(ctx) if ctx else ui.Style.detect())
    )
    try:
        emit(value, params.get("output"))
    except ToolError:
        print("Error: could not write output.", file=sys.stderr)
    return 3


def main(argv=None):
    args = sys.argv[1:] if argv is None else list(argv)
    ctx = None
    try:
        with cli.make_context("appsec-cli", args) as ctx:
            return cli.invoke(ctx)
    except click.exceptions.Exit as exc:
        return exc.exit_code
    except click.exceptions.NoArgsIsHelpError as exc:
        click.echo(exc.ctx.get_help())
        return 0
    except click.ClickException as exc:
        usage(exc)
        return 2
    except (KeyboardInterrupt, click.exceptions.Abort):
        return 130
    except Exception as exc:
        return failed(ctx, exc)


if __name__ == "__main__":
    sys.exit(main())
