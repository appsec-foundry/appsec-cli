import os
from pathlib import Path
from typing import Annotated, Optional
from urllib.parse import urlsplit

import click
import typer
from pydantic import BaseModel
from appsec_cli import Diagnostic, Finding, Result, ToolError, command
from appsec_cli.external import engine, invoke, json_object


class Area(BaseModel):
    area: str
    score: int | None
    rating: str
    reason: str | None = None


class Overview(BaseModel):
    languages: dict[str, int]
    files_read: int | None
    lines: int | None
    frameworks: list[str]
    routes: int | None
    runtimes: list[str]
    ci: list[str]
    security_tools: list[str]


class Score(BaseModel):
    score: int | None
    rating: str
    areas: list[Area] | None = None
    overview: Overview | None = None


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


# Engine options that stay with this adapter. Everything else is passed on.
ENGINE_OWNED = (
    # The adapter reads the engine's JSON and presents the result itself.
    "--json",
    "--yaml",
    "--quiet",
    "--quite",
    "--legacy-score",
    # Information modes without an assessment.
    "-h",
    "--help",
    "--version",
    "--list-rules",
    "--list-checks",
    "--verify-rules",
    # Would replace the engine version pinned by this release.
    "--update",
    # The adapter selects what is assessed and reports it as the target.
    "--repo",
    "--patch",
    "--diff",
    "--base",
    "--head",
    "--commit",
    "--staged",
    "--unstaged",
    "--worktree",
    "--pr",
    "--mr",
    # The adapter hands GIT_TOKEN to github.com and gitlab.com only.
    "--token-env",
)


def details(model):
    """Area scores and the technology overview of a --details run."""
    areas = [
        Area(
            area=row["title"],
            score=row.get("score"),
            rating=row["rating"],
            reason=row.get("reason"),
        )
        for row in model["subscores"]
    ]
    raw = model.get("overview") or {}
    files = raw.get("files") or {}
    development = raw.get("development") or {}
    overview = Overview(
        languages={row["language"]: row["files"] for row in raw.get("languages", [])},
        files_read=files.get("read"),
        lines=files.get("lines"),
        frameworks=raw.get("frameworks", []),
        routes=(raw.get("routes") or {}).get("total"),
        runtimes=[
            f"{row['runtime']} {row['version']}" for row in raw.get("runtimes", [])
        ],
        ci=[row["system"] for row in development.get("ci", [])],
        security_tools=development.get("security_tools", []),
    )
    return areas, overview


def render_details(data):
    """The overview and area scores above the findings; nothing without --details."""
    lines = []
    overview = data.get("overview")
    if overview:
        files = (
            f"{overview['files_read']:,} read, {overview['lines'] or 0:,} lines"
            if overview["files_read"] is not None
            else ""
        )
        rows = [
            (
                "Languages",
                ", ".join(f"{k} {v:,}" for k, v in overview["languages"].items()),
            ),
            ("Files", files),
            ("Frameworks", ", ".join(overview["frameworks"])),
            ("Routes", "" if overview["routes"] is None else f"{overview['routes']:,}"),
            ("Runtimes", ", ".join(overview["runtimes"])),
            ("CI", ", ".join(overview["ci"])),
            ("Security tools", ", ".join(overview["security_tools"])),
        ]
        lines += ["Overview", *(f"  {k:<15} {v}" for k, v in rows if v)]
    areas = data.get("areas")
    if areas:
        width = max(len(row["area"]) for row in areas)
        lines += ["", "Areas"] if lines else ["Areas"]
        for row in areas:
            points = "—" if row["score"] is None else str(row["score"])
            lines.append(f"  {row['area']:<{width}}  {points:>3}  {row['rating']}")
            if row.get("reason"):
                lines.append(f"    {row['reason']}")
    return lines


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
    engine_distribution="appsec-security-score",
    data=Score | Change,
    findings=True,
    render_data=render_details,
    list_findings=True,
    forward_except=ENGINE_OWNED,
)
def score(
    ctx: typer.Context,
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
    show_details: Annotated[
        bool,
        typer.Option(
            "--details",
            "--detail",
            help="Also show area scores and a technology overview.",
        ),
    ] = False,
) -> Result:
    """Score a repository, a commit or its staged changes.

    A GitHub or GitLab repository is read over HTTPS without a clone. For a
    private one on github.com or gitlab.com, put a read-only token in the
    GIT_TOKEN environment variable.
    """
    if repo_option is not None:
        source = ctx.get_parameter_source("repo")
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
    if show_details and (commit or staged):
        raise typer.BadParameter("--details applies to a repository score.")
    source = repo if url else str(Path(repo).resolve())
    argv = [engine("security-score"), source, "--json"]
    if show_details:
        argv.append("--details")
    if commit:
        import re

        if not re.fullmatch(r"HEAD|[0-9a-fA-F]{4,64}", commit):
            raise typer.BadParameter("Use HEAD or a hexadecimal commit ID.")
        argv += ["--commit", commit]
    if staged:
        argv.append("--staged")
    argv += ctx.args  # last, so that a "--" among them affects only these
    env = None
    if url and urlsplit(repo).netloc not in ("github.com", "gitlab.com"):
        # The engine would send GIT_TOKEN to any other host that asks for it.
        env = {k: v for k, v in os.environ.items() if k != "GIT_TOKEN"}
    stderr = bytearray()
    rc, raw = invoke(argv, env=env, stderr=stderr)
    if ctx.args and rc == 2 and not raw.strip():
        # The engine reports a rejected option as "security-score: error: <reason>".
        last = stderr.decode(errors="replace").strip().rsplit("\n", 1)[-1]
        prefix = "security-score: error: "
        if last.startswith(prefix):
            raise click.UsageError(
                "The engine rejected an option: " + last[len(prefix) :], ctx
            )
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
        if show_details:
            data.areas, data.overview = details(model)
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
