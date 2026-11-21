from pathlib import Path
from typing import Annotated

import typer
from appsec_cli import Result, ToolError, command
from appsec_cli.external import engine, invoke, json_object
from pydantic import JsonValue


@command(engine_distribution="appsec-analyzer", data=dict[str, JsonValue])
def profile(
    repo: Annotated[Path, typer.Argument(help="Repository to inventory.")] = Path("."),
) -> Result:
    """Inventory repository size, languages and manifests without a model call."""
    code, out = invoke(
        [engine("appsec-analyzer"), "repo-profile", str(repo.resolve()), "--json"]
    )
    if code:
        raise ToolError(
            "profile_failed", "Analyzer could not profile the selected repository."
        )
    return Result(summary="Repository inventory complete.", data=json_object(out))


@command(engine_distribution="appsec-analyzer", data=dict[str, JsonValue])
def export(
    assessment: Path,
    destination: Path,
    format: Annotated[
        str, typer.Option(help="Export format: sarif or html.")
    ] = "sarif",
) -> Result:
    """Export a saved assessment to a directory."""
    if format not in ("sarif", "html"):
        raise typer.BadParameter("Choose sarif or html.")
    code, _ = invoke(
        [
            engine("appsec-analyzer"),
            "export",
            "--assessment",
            str(assessment.resolve()),
            "--output",
            str(destination.resolve()),
            "--formats",
            format,
        ]
    )
    if code:
        raise ToolError("export_failed", "Analyzer could not export this assessment.")
    return Result(
        summary="Assessment exported.",
        data={"directory": str(destination), "format": format},
    )
