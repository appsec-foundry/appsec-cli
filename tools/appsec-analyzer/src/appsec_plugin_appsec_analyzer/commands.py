import typer
from appsec_cli import Passthrough, Result, ToolError, command
from appsec_cli.external import check_usage, engine, invoke, json_object, last_line
from pydantic import JsonValue


def run(ctx, *command_args):
    """Start the Analyzer with the fixed arguments, then everything the user gave."""
    stderr = bytearray()
    code, out = invoke(
        [engine("appsec-analyzer"), *command_args, *ctx.args], stderr=stderr
    )
    check_usage(code, out, stderr)
    return code, out, last_line(stderr)


def terminal(*command_args):
    """In the terminal the Analyzer prints its own output and sets the exit code."""

    def call(ctx: typer.Context) -> Passthrough:
        return Passthrough([engine("appsec-analyzer"), *command_args, *ctx.args])

    return call


@command(
    data=dict[str, JsonValue],
    forward_except=(),
    passthrough=terminal("repo-profile"),
    engine_help=("appsec-analyzer", "repo-profile", "--help"),
)
def profile(ctx: typer.Context) -> Result:
    """Inventory repository size, languages and manifests without a model call."""
    code, out, reason = run(ctx, "repo-profile", "--json")
    if code:
        raise ToolError(
            "profile_failed",
            reason or "Analyzer could not profile the selected repository.",
        )
    return Result(summary="Repository inventory complete.", data=json_object(out))


@command(
    data=dict[str, JsonValue],
    forward_except=(),
    passthrough=terminal("export"),
    engine_help=("appsec-analyzer", "export", "--help"),
)
def export(ctx: typer.Context) -> Result:
    """Export a saved assessment, for example as SARIF or HTML."""
    code, _, reason = run(ctx, "export")
    if code:
        raise ToolError(
            "export_failed", reason or "Analyzer could not export this assessment."
        )
    return Result(summary="Assessment exported.")
