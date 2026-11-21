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


def unclear(row):
    return row["status"] == "unclear" or any(
        location["status"] == "unclear" for location in row.get("locations", [])
    )


def run_status(rc, model):
    """Engine exit 2 also reports a rating limited by missing control evidence.

    That run is complete. Only source the engine could not cover makes it partial.
    """
    if rc == 0:
        return "ok", None
    if rc == 2 and not any(
        check["area"] == "coverage" and unclear(check) for check in model["checks"]
    ):
        return "ok", Diagnostic(
            level="info",
            code="limited_evidence",
            message="Some areas lack evidence for a positive rating.",
        )
    return "partial", Diagnostic(
        level="warning", code="limited_coverage", message="Coverage is incomplete."
    )


def finding(row):
    path = row.get("path") or row.get("file")
    location = {"kind": "file", "path": path}
    if isinstance(row.get("line"), int) and row["line"] > 0:
        location["start_line"] = row["line"]
    fix = row.get("next_action")
    return Finding(
        rule="security-score/" + row["rule"],
        severity=row["severity"],
        title=row.get("title") or row["rule"],
        locations=[location] if isinstance(path, str) else None,
        remediation=fix if isinstance(fix, str) else None,
    )


@command(
    engine_distribution="appsec-security-score", data=Score | Change, findings=True
)
def score(
    repo: Annotated[
        Path,
        typer.Argument(
            help="Local repository directory.", exists=True, file_okay=False
        ),
    ] = Path("."),
    commit: Annotated[
        Optional[str], typer.Option(help="Review a single commit.")
    ] = None,
    staged: Annotated[
        bool, typer.Option("--staged", help="Review staged changes.")
    ] = False,
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
    if rc not in (0, 1, 2) or model.get("analysis") not in (
        "security-assessment",
        "change-relevance",
    ):
        raise ToolError(
            "score_failed", "The scoring engine could not complete its assessment."
        )
    status, diagnostic = run_status(rc, model)
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
        summary = (
            f"Score {points}/100 ({rating})"
            if points is not None
            else f"Score: {rating}"
        )
    target = {"kind": "commit" if commit else "repository", "path": str(repo.resolve())}
    if commit:
        target["revision"] = commit
    if staged:
        target["staged"] = True
    return Result(
        status=status,
        summary=summary,
        target=target,
        data=data.model_dump(),
        findings=[finding(row) for row in model.get("findings", [])],
        diagnostics=[diagnostic] if diagnostic else None,
    )
