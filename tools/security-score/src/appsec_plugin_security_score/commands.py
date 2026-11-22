import os
import re
from urllib.parse import urlsplit

import typer
from pydantic import BaseModel
from appsec_cli import Diagnostic, Finding, Passthrough, Result, ToolError, command
from appsec_cli.external import check_usage, engine, invoke, json_object, last_line


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


# Engine options appsec-cli does not pass on. Everything else goes to the engine.
ENGINE_OWNED = (
    # Would replace the engine version pinned by this release.
    "--update",
    # Starts a program of the caller's choice.
    "--analyzer",
    # Selects the secret the engine sends; GIT_TOKEN reaches github.com and
    # gitlab.com only.
    "--token-env",
)
# Refused only with --format json or sarif, where the adapter reads the engine's
# JSON and presents the result itself. In the terminal the engine prints them.
JSON_OWNED = (
    "--json",
    "--yaml",
    "--quiet",
    "--quite",
    "--legacy-score",
    # Information modes without an assessment.
    "--version",
    "--list-rules",
    "--list-checks",
    "--verify-rules",
)
TOKEN_HOSTS = ("github.com", "gitlab.com")
URL = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://[^\s,]+")


def token_allowed(urls):
    """Whether every URL in the arguments is an HTTPS address on a token host."""
    return all(
        urlsplit(url).scheme == "https" and urlsplit(url).netloc in TOKEN_HOSTS
        for url in urls
    )


def engine_env(urls):
    """None keeps GIT_TOKEN; otherwise the environment without it.

    The engine would send GIT_TOKEN to any other host that asks for it.
    """
    if token_allowed(urls):
        return None
    return {k: v for k, v in os.environ.items() if k != "GIT_TOKEN"}


def target(scope):
    """What the engine assessed, as it reports it in its scope."""
    found = {"kind": "change" if scope.get("kind") == "change" else "repository"}
    where = scope.get("repository")
    if isinstance(where, str):
        found["url" if scope.get("selection") == "git-url" else "path"] = where
    for key in ("base", "head"):
        if isinstance(scope.get(key), str):
            found[key] = scope[key]
    revision = scope.get("revision") or scope.get("head")
    if isinstance(revision, str):
        found["revision"] = revision
    return found


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


def terminal(ctx: typer.Context) -> Passthrough:
    """In the terminal the engine prints the result and sets the exit code."""
    args = list(ctx.args)
    urls = [url for arg in args for url in URL.findall(arg)]
    return Passthrough([engine("security-score"), *args], env=engine_env(urls))


@command(
    engine_distribution="appsec-security-score",
    data=Score | Change,
    findings=True,
    forward_except=ENGINE_OWNED,
    json_except=JSON_OWNED,
    passthrough=terminal,
    engine_help=("security-score", "--help"),
)
def score(ctx: typer.Context) -> Result:
    """Score a repository, a commit or its staged changes.

    A GitHub or GitLab repository is read over HTTPS without a clone. For a
    private one on github.com or gitlab.com, put a read-only token in the
    GIT_TOKEN environment variable.
    """
    args = list(ctx.args)
    urls = [url for arg in args for url in URL.findall(arg)]
    stderr = bytearray()
    rc, raw = invoke(
        [engine("security-score"), "--json", *args],
        env=engine_env(urls),
        stderr=stderr,
    )
    check_usage(rc, raw, stderr)
    if not raw.strip():
        if urls:
            raise ToolError(
                "repository_unavailable",
                last_line(stderr)
                or "Could not read the repository. Check the URL and read access; "
                "a private repository needs GIT_TOKEN.",
            )
        raise ToolError(
            "score_failed",
            last_line(stderr)
            or "The scoring engine could not complete its assessment.",
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
        if "overview" in model:  # the engine adds it with --details
            data.areas, data.overview = details(model)
        summary = (
            f"Score {points}/100 ({rating})"
            if points is not None
            else f"Score: {rating}"
        )
    return Result(
        status=status,
        summary=summary,
        target=target(model.get("scope") or {}),
        data=data.model_dump(),
        findings=[finding(row) for row in model.get("findings", [])],
        diagnostics=[diagnostic] if diagnostic else None,
    )
