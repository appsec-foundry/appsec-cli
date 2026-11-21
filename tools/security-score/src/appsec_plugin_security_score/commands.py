import os
from pathlib import Path
from typing import Annotated, Optional
from urllib.parse import urlsplit

import click
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
        str,
        typer.Argument(
            help="Local directory or HTTPS URL of a GitHub or GitLab repository."
        ),
    ] = ".",
    repo_option: Annotated[
        Optional[str],
        typer.Option("--repo", metavar="REPO", help="Same as the REPO argument."),
    ] = None,
    commit: Annotated[
        Optional[str], typer.Option(help="Review a single commit.")
    ] = None,
    staged: Annotated[
        bool, typer.Option("--staged", help="Review staged changes.")
    ] = False,
) -> Result:
    """Score a repository, a commit or its staged changes.

    A GitHub or GitLab repository is read over HTTPS without a clone. For a
    private one on github.com or gitlab.com, put a read-only token in the
    GIT_TOKEN environment variable.
    """
    if repo_option is not None:
        source = click.get_current_context().get_parameter_source("repo")
        if source is not click.core.ParameterSource.DEFAULT:
            raise typer.BadParameter("Choose the REPO argument or --repo, not both.")
        repo = repo_option
    url = repo.startswith("https://")
    if "://" in repo and not url:
        raise typer.BadParameter("Use an HTTPS URL.", param_hint="REPO")
    if not url and not Path(repo).is_dir():
        raise typer.BadParameter(
            f"Directory '{repo}' does not exist.", param_hint="REPO"
        )
    if commit and staged:
        raise typer.BadParameter("Choose either --commit or --staged.")
    if url and (commit or staged):
        raise typer.BadParameter(
            "--commit and --staged need a local checkout of the repository."
        )
    source = repo if url else str(Path(repo).resolve())
    argv = [engine("security-score"), source, "--json"]
    if commit:
        import re

        if not re.fullmatch(r"HEAD|[0-9a-fA-F]{4,64}", commit):
            raise typer.BadParameter("Use HEAD or a hexadecimal commit ID.")
        argv += ["--commit", commit]
    if staged:
        argv.append("--staged")
    env = None
    if url and urlsplit(repo).netloc not in ("github.com", "gitlab.com"):
        # The engine would send GIT_TOKEN to any other host that asks for it.
        env = {k: v for k, v in os.environ.items() if k != "GIT_TOKEN"}
    rc, raw = invoke(argv, env=env)
    if url and not raw.strip():
        raise ToolError(
            "repository_unavailable",
            "Could not read the repository. Check the URL and read access; "
            "a private repository needs GIT_TOKEN.",
        )
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
    target = {"kind": "commit" if commit else "repository"}
    target["url" if url else "path"] = source
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
