import json
import os

import click
import typer
from appsec_cli import Passthrough, Result, ToolError, command
from appsec_cli.external import check_usage, engine, invoke, json_object, last_line
from pydantic import JsonValue

# The Harvester ends a run itself after max-run-seconds of its configuration,
# at most a day, and a sign-in after 300 seconds. appsec-cli stops it only when
# it hangs beyond that.
LIMIT = 86400 + 60
# Exit codes of a failed Harvester command; 2 is an invalid configuration.
FAILURES = {3: "auth_failed", 4: "harvest_failed", 5: "export_failed"}


def engine_env():
    """The environment without GIT_TOKEN.

    The configuration names the variables whose values the Harvester sends to
    a source. GIT_TOKEN reaches github.com and gitlab.com only.
    """
    return {k: v for k, v in os.environ.items() if k != "GIT_TOKEN"}


def reason(stderr):
    """The error the Harvester reports as JSON on its last line of stderr."""
    line = last_line(stderr)
    try:
        message = json.loads(line)["error"]
    except (ValueError, TypeError, KeyError, RecursionError):
        return line
    return message if isinstance(message, str) else line


def harvest(ctx, name):
    """Run a Harvester command with everything the user gave; return its stdout."""
    stderr = bytearray()
    code, out = invoke(
        [engine("requirement-harvester"), name, *ctx.args],
        env=engine_env(),
        timeout=LIMIT,
        stderr=stderr,
    )
    check_usage(code, out, stderr)
    if code == 2:
        raise click.UsageError(
            reason(stderr) or "The configuration is invalid.",
            click.get_current_context(silent=True),
        )
    if code:
        raise ToolError(
            FAILURES.get(code, "harvest_failed"),
            reason(stderr) or "The Harvester could not complete the command.",
        )
    return out


def options(name):
    """In the terminal the Harvester prints its own output and sets the exit code."""

    def terminal(ctx: typer.Context) -> Passthrough:
        return Passthrough(
            [engine("requirement-harvester"), name, *ctx.args],
            env=engine_env(),
            timeout=LIMIT,
        )

    return dict(
        data=dict[str, JsonValue],
        forward_except=(),
        passthrough=terminal,
        engine_help=("requirement-harvester", name, "--help"),
    )


@command(**options("validate"))
def validate(ctx: typer.Context) -> Result:
    """Check a configuration without network access."""
    harvest(ctx, "validate")
    return Result(summary="Configuration valid; no network access made.")


@command(**options("run"))
def run(ctx: typer.Context) -> Result:
    """Read requirements from the configured pages into an OSCAL catalog."""
    data = json_object(harvest(ctx, "run"))
    if data.get("dry-run") is True:
        return Result(summary="Dry run complete; no catalog written.", data=data)
    return Result(summary="Run complete.", data=data)


@command(**options("login"))
def login(ctx: typer.Context) -> Result:
    """Sign in to a source that uses Microsoft Entra ID."""
    raise click.UsageError(
        "login signs in through the browser; run it without --format json.",
        click.get_current_context(silent=True),
    )
