"""Console entry point: one click group. A tool is imported only when selected."""

import difflib
import json
import os
import shutil
import subprocess
import sys
import time
import traceback
from datetime import datetime, timezone
from importlib.metadata import metadata, version

import click
import typer
from click.core import ParameterSource
from typer.core import TyperCommand
from typer.main import get_command

from . import ui, updates
from .catalog import discover
from .config import settings, threshold
from .external import attached, engine, invoke
from .output import emit, finalize, sarif
from .sdk import SEVERITIES, Envelope, Passthrough, Result, ToolError


class UsageError(click.UsageError):
    """A usage error with an optional hint for the next step."""

    def __init__(self, message, hint=None, ctx=None):
        super().__init__(message, ctx)
        self.hint = hint


def suggest(name, names):
    match = difflib.get_close_matches(name, names, n=1)
    return f"Did you mean '{match[0]}'?" if match else None


def unknown_tool(name, names):
    return UsageError(
        f"Unknown tool '{name}'.",
        suggest(name, names) or "See 'appsec-cli tools list'.",
    )


def disabled_tool(name):
    return UsageError(
        f"Tool '{name}' is disabled.", "See 'appsec-cli tools list --all'."
    )


def listing(rows):
    """The JSON of the start page and of tools list."""
    return {"schema_version": 1, "version": version("appsec-cli"), "tools": rows}


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


def interactive():
    return sys.stdin.isatty() and sys.stderr.isatty()


def notify(ctx):
    """After a result in the terminal: once a day, whether a newer release exists."""
    if options(ctx)["format"] != "table" or not interactive():
        return
    text = updates.hint()
    if text:
        print("\n" + style_for(ctx)(text, "muted"), file=sys.stderr)


def tagline():
    """The suite's one-line description, which the AppSec team sets in its pyproject.toml."""
    return metadata("appsec-cli").get("Summary", "")


def write_examples(formatter, examples):
    """The Examples section at the end of a tool's help."""
    if examples:
        formatter.write_paragraph()
        formatter.write("\n".join(ui.example_lines(examples)) + "\n")


class Forwarding(TyperCommand):
    """A wrapper command: all its arguments belong to the engine.

    appsec-cli passes them on unchanged. It refuses only the reserved engine
    options and their abbreviations, since argparse engines accept abbreviated
    option names. -h and --help show the engine's own help.
    """

    reserved = frozenset()
    engine_help = None

    def parse_args(self, ctx, args):
        options = args[: args.index("--")] if "--" in args else args
        if any(token in ctx.help_option_names for token in options):
            return super().parse_args(ctx, ["--help"])
        blocked = self.reserved | set(ctx.help_option_names)
        for token in options:
            name = token.split("=", 1)[0]
            if name.startswith("--"):
                hit = len(name) > 2 and any(o.startswith(name) for o in blocked)
            else:
                hit = name.startswith("-") and name[:2] in blocked
            if hit:
                raise UsageError(
                    f"Option '{name}' cannot be passed to the engine.", None, ctx
                )
        super().parse_args(ctx, [])
        ctx.args = list(args)
        return ctx.args

    def format_options(self, ctx, formatter):
        kept = ", ".join(sorted(self.reserved))
        formatter.write_paragraph()
        formatter.write_text(
            "Arguments and options go to the engine unchanged"
            + (f", except {kept}." if kept else ".")
        )
        text = engine_help_text(self.engine_help)
        if text:
            formatter.write_paragraph()
            formatter.write(text)


def engine_help_text(argv):
    """The engine's own help, or "" when it cannot be read."""
    if not argv:
        return ""
    try:
        code, raw = invoke([engine(argv[0]), *argv[1:]], timeout=10, cap=256 * 1024)
    except ToolError:
        return ""
    if code:
        return ""
    return "".join(
        ui.clean(line) + "\n" for line in raw.decode(errors="replace").splitlines()
    )


def as_command(spec, examples=(), table=False):
    """The click command of a spec; in the terminal a wrapper may hand over."""
    app = typer.Typer(
        add_completion=False, rich_markup_mode=None, pretty_exceptions_enable=False
    )
    forwarding = spec.forward_except is not None
    through = table and spec.passthrough is not None
    handler = spec.handler
    if through:

        def handler(ctx: typer.Context):
            return spec.passthrough(ctx)

        handler.__doc__ = spec.handler.__doc__
    if forwarding:
        app.command(cls=Forwarding, options_metavar="[ARGS]...")(handler)
    else:
        app.command()(handler)
    command = get_command(app)
    if forwarding:
        if command.params:
            raise ToolError(
                "invalid_plugin",
                "A command that hands its arguments to the engine declares none.",
            )
        # Options for the engine's JSON are refused only where appsec-cli reads it.
        command.reserved = frozenset(
            spec.forward_except if through else spec.forward_except + spec.json_except
        )
        command.engine_help = spec.engine_help
    command.format_epilog = lambda ctx, formatter: write_examples(formatter, examples)
    return command


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
    return as_command(
        spec, tool.examples(subcommand), options(ctx)["format"] == "table"
    )


class ToolGroup(click.Group):
    """A tool with several commands, such as appsec-analyzer export."""

    def __init__(self, tool):
        super().__init__(tool.name, help=tool.summary)
        self.tool = tool

    def list_commands(self, ctx):
        return sorted(self.tool.commands)

    def format_commands(self, ctx, formatter):
        """The commands with the summaries of the tool list, without loading them."""
        usage = self.tool.description()["usage"]
        if all(item["summary"] for item in usage):
            with formatter.section("Commands"):
                formatter.write_dl(
                    [
                        (item["command"].split()[-1], ui.clean(item["summary"]))
                        for item in usage
                    ]
                )
        else:
            super().format_commands(ctx, formatter)

    def format_epilog(self, ctx, formatter):
        write_examples(
            formatter,
            [
                item
                for name in self.list_commands(ctx)
                for item in self.tool.examples(name)
            ],
        )

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
            raise disabled_tool(name)
        ctx.meta["appsec.tool"] = name
        if tool.status != "unchecked":
            raise ToolError("tool_" + tool.status, f"{name} is {tool.status}.")
        return loaded(ctx, tool, "") if "" in tool.commands else ToolGroup(tool)

    def resolve_command(self, ctx, args):
        command = self.get_command(ctx, args[0])
        if command is None:
            raise unknown_tool(args[0], self.list_commands(ctx))
        return args[0], command, args[1:]

    def format_help(self, ctx, formatter):
        rows = [p.get_help_record(ctx) for p in self.get_params(ctx)]
        formatter.write(
            ui.overview(
                enabled_rows(ctx), style_for(ctx), version("appsec-cli"), tagline()
            )
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
# Eager, so that --help, which is eager too, sees it when it comes first.
@click.option(
    "--no-color", is_flag=True, is_eager=True, help="Print text without colour."
)
@click.option("-v", "--verbose", is_flag=True, help="Show diagnostic codes.")
@click.option("--debug", is_flag=True, help="Show the traceback when a run fails.")
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
        code = publish(
            ctx,
            listing(rows),
            lambda: ui.overview(rows, style_for(ctx), version("appsec-cli"), tagline()),
        )
        notify(ctx)
        return code


@cli.result_callback()
@click.pass_context
def finish(ctx, result, **params):
    """Turn a tool's result into the report and the exit code."""
    if "appsec.run" not in ctx.meta:
        return result or 0
    tool, spec, start, started = ctx.meta["appsec.run"]
    if isinstance(result, Passthrough):
        return hand_over(ctx, tool.name, result)
    if not isinstance(result, Result):
        raise ToolError("invalid_result", "The plugin returned an invalid result.")
    cfg, _ = state(ctx)
    explicit = params["fail_on"] or os.getenv("APPSEC_CLI_FAIL_ON")
    if explicit:
        fail, ignored = threshold(explicit), False
    else:
        fail, ignored = cfg.threshold_for(tool.name, spec.fail_on)
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
    if ignored:
        report.setdefault("diagnostics", []).append(
            {
                "level": "warning",
                "code": "config_threshold_ignored",
                "message": f".appsec-cli.toml cannot lower the threshold; {fail} applies.",
            }
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
    notify(ctx)
    return code


# Global options that act on the common result, which a terminal run does not produce.
RESULT_OPTIONS = {
    "output": "--output",
    "fail_on": "--fail-on",
    "min_severity": "--min-severity",
    "limit": "--limit",
}


def hand_over(ctx, name, call):
    """Run a wrapper's engine in the terminal: its output and exit code are the result.

    A threshold, filter or output file chosen for this run is refused rather than
    ignored, so that a job relying on it fails instead of passing unchecked.
    """
    root = ctx.find_root()
    given = [
        option
        for param, option in RESULT_OPTIONS.items()
        if root.get_parameter_source(param) not in (None, ParameterSource.DEFAULT)
    ]
    if os.getenv("APPSEC_CLI_FAIL_ON"):
        given.append("APPSEC_CLI_FAIL_ON")
    if given:
        raise UsageError(
            f"{given[0]} needs --format json or sarif.",
            f"In the terminal, {name} shows its engine's output and exit code.",
        )
    env = call.env
    if options(ctx)["no_color"]:
        env = {**(os.environ if env is None else env), "NO_COLOR": "1"}
    code = attached(call.argv, env=env)
    if code == 2:
        # argparse engines end with 2 on an option they do not know, such as a
        # global option of appsec-cli given after the tool name.
        names = global_options(root) - set(root.help_option_names) - {"--version"}
        given = (arg.split("=", 1)[0] for arg in call.argv[1:])
        option = next((arg for arg in given if arg in names), None)
        if option:
            hint = f"{option} is a global option. " + before_tool(option, name)
            print(f"Hint: {ui.clean(hint)}", file=sys.stderr)
    notify(ctx)
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
        listing(rows),
        lambda: ui.tool_list(rows, style_for(ctx)),
    )


@tools_group.command("describe")
@click.argument("name")
@click.pass_context
def tools_describe(ctx, name):
    """Show the arguments, output formats and data schema of a tool."""
    _, tools = state(ctx)
    if name not in tools:
        raise unknown_tool(name, list(tools))
    if tools[name].status == "disabled":
        raise disabled_tool(name)
    result = describe(tools[name], options(ctx)["format"] == "table")
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
    installation = updates.pipx_metadata()
    if not pipx or installation is None:
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
    warnings = []
    if installation.get("injected_packages"):
        # Separately: a plugin that pipx cannot update must not fail the suite update.
        try:
            plugins = subprocess.run(
                [pipx, "upgrade", "--include-injected", "appsec-cli"],
                capture_output=True,
                text=True,
                timeout=900,
            ).returncode
        except subprocess.TimeoutExpired:
            plugins = 1
        if plugins:
            warnings.append(
                "Not every plugin added with 'pipx inject' could be updated. "
                "A plugin injected from a wheel file updates only from a package "
                "index that has it."
            )
    new_suite, new_tools = installed()
    data = {
        "schema_version": 1,
        "before": {"version": suite, "tools": tools},
        "after": {"version": new_suite, "tools": new_tools},
    }
    if warnings:
        data["warnings"] = warnings
    return publish(ctx, data, lambda: ui.changes(data, style_for(ctx)))


BUILTIN = {"schema": schema, "tools": tools_group, "update": update}


def describe(tool, table=False):
    if tool.status != "unchecked":
        raise ToolError("tool_" + tool.status, f"{tool.name} is {tool.status}.")
    definitions = []
    for name in sorted(tool.commands):
        spec = tool.load(name)
        cmd = as_command(spec, table=table)
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
                    **(
                        {"forwards_except": sorted(cmd.reserved)}
                        if spec.forward_except is not None
                        else {}
                    ),
                }
            )
    return {"schema_version": 1, **tool.description(), "definitions": definitions}


def plain(value):
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    return str(value)


def global_options(root):
    """The option names of appsec-cli itself, which go before the tool name."""
    return {o for p in root.command.params for o in p.opts}


def before_tool(option, path):
    """The hint for a global option that came after the tool name."""
    return f"Put it before the tool name: appsec-cli {option} … {path} …"


def usage(exc):
    """Print a usage error and, where it helps, the next step."""
    message, hint = exc.format_message(), getattr(exc, "hint", None)
    root = exc.ctx.find_root() if exc.ctx else None
    if root and exc.ctx is not root:
        path = exc.ctx.command_path.removeprefix("appsec-cli ")
        names = global_options(root)
        if isinstance(exc, click.NoSuchOption) and exc.option_name in names:
            message = f"{exc.option_name} is a global option."
            hint = before_tool(exc.option_name, path)
        if hint is None:
            # A wrapper hands global options after the tool name to the engine.
            given = [a.split("=", 1)[0] for a in exc.ctx.args]
            option = next((a for a in given if a in names and a in message), None)
            if option:
                hint = f"{option} is a global option. " + before_tool(option, path)
    if hint is None and exc.ctx:
        hint = f"Run '{exc.ctx.command_path} --help'."
    print(f"Error: {ui.clean(message)}", file=sys.stderr)
    if hint:
        print(f"Hint: {ui.clean(hint)}", file=sys.stderr)


def trace(exc):
    """Print the traceback of an error and of the errors it replaced, oldest first."""
    chain = []
    while exc is not None and exc not in chain:
        chain.append(exc)
        exc = exc.__cause__ or exc.__context__
    for item in reversed(chain):
        traceback.print_exception(
            type(item), item, item.__traceback__, chain=False, file=sys.stderr
        )


def failed(ctx, exc):
    """Report a run that could not produce a result; exit code 3."""
    known = isinstance(exc, ToolError)
    code = exc.code if known else "internal_error"
    message = str(exc) if known else "The command did not produce a valid result."
    params = options(ctx) if ctx else {}
    if params.get("debug"):
        trace(exc)
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
