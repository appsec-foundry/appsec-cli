from pathlib import Path
from typing import Annotated, Optional

import typer
from pydantic import BaseModel
from appsec_cli import Diagnostic, Finding, Result, ToolError, command
from appsec_cli.external import engine, invoke, json_object


class Score(BaseModel):
    score: int | None
    rating: str


class Change(BaseModel):
    relevance: str


@command(
    engine_distribution="appsec-security-score", data=Score | Change, findings=True
)
def score(
    repo: Annotated[Path, typer.Argument(help="Local repository directory.")] = Path(
        "."
    ),
    commit: Annotated[
        Optional[str], typer.Option(help="Review a single commit.")
    ] = None,
    staged: Annotated[bool, typer.Option(help="Review staged changes.")] = False,
) -> Result:
    """Score a repository, a commit or its staged changes."""
    if commit and staged:
        raise typer.BadParameter("Choose either --commit or --staged.")
    argv = [engine("security-score"), str(repo.resolve()), "--json"]
    if commit:
        import re

        if not re.fullmatch(r"HEAD|[0-9a-fA-F]{4,64}", commit):
            raise typer.BadParameter("Use HEAD or a hexadecimal commit ID.")
        argv += ["--commit", commit]
    if staged:
        argv.append("--staged")
    rc, raw = invoke(argv)
    model = json_object(raw)
    partial = rc != 0
    if rc not in (0, 1, 2) or model.get("analysis") not in (
        "security-assessment",
        "change-relevance",
    ):
        raise ToolError(
            "score_failed", "The scoring engine could not complete its assessment."
        )
    if model["analysis"] == "change-relevance":
        data = Change(relevance=model["relevance"])
        summary = f"Security relevance: {data.relevance}."
    else:
        rating = model["overall"]["rating"]
        values = [
            row["score"] for row in model["subscores"] if row.get("score") is not None
        ]
        points = min(values) if values and rating != "Not assessed" else None
        data = Score(score=points, rating=rating)
        summary = f"{points}/100 ({rating})" if points is not None else rating
    findings = []
    for row in model.get("findings", []):
        loc = row.get("path") or row.get("file")
        findings.append(
            Finding(
                rule="security-score/" + row["rule"],
                severity=row["severity"],
                title=row.get("title") or row["rule"],
                locations=[{"kind": "file", "path": loc}]
                if isinstance(loc, str)
                else None,
            )
        )
    return Result(
        status="partial" if partial else "ok",
        summary=summary,
        data=data.model_dump(),
        findings=findings,
        diagnostics=[
            Diagnostic(
                level="warning",
                code="limited_coverage",
                message="Coverage is incomplete.",
            )
        ]
        if partial
        else None,
    )
