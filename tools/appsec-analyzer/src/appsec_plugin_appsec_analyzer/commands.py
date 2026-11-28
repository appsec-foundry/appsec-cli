import typer
from appsec_cli import Passthrough, Result, ToolError, command
from appsec_cli.external import (
    check_usage,
    engine,
    git_token_env,
    invoke,
    json_object,
    last_line,
)
from pydantic import JsonValue


def run(ctx, *command_args):
    """Start the Analyzer with the fixed arguments, then everything the user gave."""
    stderr = bytearray()
    code, out = invoke(
        [engine("appsec-analyzer"), *command_args, *ctx.args], stderr=stderr
    )
    check_usage(code, out, stderr)
    return code, out, last_line(stderr)


def terminal(*command_args, timeout=120):
    """In the terminal the Analyzer prints its own output and sets the exit code.

    GIT_TOKEN reaches the engine only for github.com and gitlab.com.
    """

    def call(ctx: typer.Context) -> Passthrough:
        return Passthrough(
            [engine("appsec-analyzer"), *command_args, *ctx.args],
            env=git_token_env(ctx.args),
            timeout=timeout,
        )

    return call


# assess bounds its run itself (--max-duration, --budget, --max-calls), and the
# user can raise those limits, so appsec-cli sets none.
@command(
    data=dict[str, JsonValue],
    forward_except=(),
    passthrough=terminal("assess", timeout=None),
    engine_help=("appsec-analyzer", "assess", "--help"),
    terminal_only="Its reports, SARIF among them, go to --output.",
)
def assess(ctx: typer.Context) -> Result:
    """Run a full security assessment with a model.

    The Analyzer sends the repository's source to the profile's model and
    stops at the cost limit, by default USD 12, 20 or 40 for quick, standard
    or thorough. For a private repository on github.com or gitlab.com, put a
    read-only token in the GIT_TOKEN environment variable; other hosts don't
    receive it.
    """


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
