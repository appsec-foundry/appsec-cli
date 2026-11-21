import os
import re
from contextlib import nullcontext
from pathlib import Path
from typing import Annotated, Optional, Literal

import typer
from pydantic import BaseModel, ConfigDict, ValidationError
from appsec_cli import Diagnostic, Finding, Result, ToolError, command
from appsec_cli.sdk import SEVERITIES, Severity
from . import hosts, source


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class Threat(Strict):
    title: str
    severity: Severity
    path: str
    side: Literal["before", "after", "context"]
    line: int
    impact: str
    actor: str
    prerequisites: str
    change: Literal["introduced", "changed", "existing", "mitigated"]
    existing_controls: str
    remediation: str


class Architecture(Strict):
    assets: list[str]
    data_flows: list[str]
    trust_boundaries: list[str]


class Review(Strict):
    architecture: Architecture
    threats: list[Threat]
    open_questions: list[str]


class Details(Strict):
    architecture: Architecture
    profile: str
    model: str
    revision: str
    base: str | None
    included: int
    omitted: int
    omission_reasons: dict[str, int]
    open_questions: list[str]
    threats: list[Threat]


def render_review(data):
    lines = [
        f"Revision {data['revision']} · {data['included']} source entries reviewed, {data['omitted']} omitted"
    ]
    for key, label in (
        ("assets", "Assets"),
        ("data_flows", "Data flows"),
        ("trust_boundaries", "Trust boundaries"),
    ):
        if data["architecture"][key]:
            lines.extend(["", label])
            lines.extend("  " + item for item in data["architecture"][key])
    for threat in data["threats"]:
        lines.extend(
            [
                "",
                f"{threat['severity'].upper()} · {threat['change']} · {threat['title']} ({threat['path']}:{threat['line']}, {threat['side']})",
                f"  Actor and conditions: {threat['actor']}. {threat['prerequisites']}",
                "  Impact: " + threat["impact"],
                "  Controls: " + threat["existing_controls"],
                "  Mitigation: " + threat["remediation"],
            ]
        )
    if data["open_questions"]:
        lines.extend(["", "Open questions"])
        lines.extend("  " + question for question in data["open_questions"])
    return lines


@command(
    render_data=render_review,
    engine_distribution="appsec-analyzer",
    data=Details,
    findings=True,
    fail_on="never",
)
def analyze(
    repo: Annotated[
        Path,
        typer.Argument(
            help="Local Git repository (committed HEAD).", exists=True, file_okay=False
        ),
    ] = Path("."),
    commit: Annotated[
        Optional[str],
        typer.Option(help="Commit SHA or HEAD; compare to its first parent."),
    ] = None,
    pr: Annotated[
        Optional[str], typer.Option(help="GitHub pull request HTTPS URL.")
    ] = None,
    profile: Annotated[
        Optional[str], typer.Option(help="claude, codex-cli, anthropic-api or litellm.")
    ] = None,
    model: Annotated[
        Optional[str], typer.Option(help="Model name or configured gateway alias.")
    ] = None,
) -> Result:
    """Assess threats with cited context. Examples: analyze-threats . | analyze-threats --commit HEAD"""
    from appsec_analyzer.engine import initialize

    initialize()
    from appsec_analyzer import review_sources

    if pr and (commit or repo != Path(".")):
        raise typer.BadParameter(
            "Use --pr alone or select a local repository and commit."
        )
    selected = profile or os.getenv("APPSEC_CLI_PROFILE") or "claude"
    defaults = {
        "claude": "sonnet",
        "codex-cli": "gpt-5.4",
        "anthropic-api": "claude-sonnet-4-6",
    }
    model = model or os.getenv("APPSEC_CLI_MODEL") or defaults.get(selected)
    if selected not in hosts.PROFILES or not model:
        raise typer.BadParameter(
            "Select a supported profile. LiteLLM requires a gateway model via --model or APPSEC_CLI_MODEL."
        )
    origin = None
    workspace = nullcontext(repo.resolve())
    if pr:
        if not re.fullmatch(
            r"https://github\.com/[A-Za-z0-9_-]+/[A-Za-z0-9_.-]+/pull/[1-9][0-9]*", pr
        ):
            raise typer.BadParameter(
                "Expected https://github.com/OWNER/REPO/pull/NUMBER."
            )
        try:
            review = review_sources.parse(pr, "pr")
            origin = review_sources.resolve(review)
        except review_sources.ReviewError:
            raise ToolError(
                "pr_unavailable",
                "Could not resolve the GitHub pull request. Check the URL and read access.",
            ) from None
        workspace = review_sources.checkout(review, origin)
    with workspace as root:
        head = origin["head"] if origin else source.revision(root, commit or "HEAD")
        base = origin["base"] if origin else None
        if commit:
            parents = (
                source.git(root, "cat-file", "-p", head)
                .split(b"\n\n", 1)[0]
                .splitlines()
            )
            base = next(
                (p[7:].decode() for p in parents if p.startswith(b"parent ")), None
            )
        docs, gaps, cleaner = source.snapshot(
            root, head, base, change=bool(pr or commit)
        )
        scope = {
            "kind": "pull_request" if pr else "commit" if commit else "repository",
            "revision": head,
            "base": base,
        }
        if pr:
            scope["url"] = pr
        reply = hosts.complete(
            selected,
            model,
            {"scope": scope, "documents": docs},
            Review.model_json_schema(),
            root,
        )
        try:
            parsed = Review.model_validate(cleaner.protect(reply))
            lengths = {
                (d["side"], d["path"]): len(d["source"].splitlines()) for d in docs
            }
            if any(
                not 1 <= t.line <= lengths.get((t.side, t.path), 0)
                for t in parsed.threats
            ):
                raise ValueError
        except (ValidationError, ValueError):
            raise ToolError(
                "llm_invalid_response",
                "Threat response failed schema or source citation validation.",
            ) from None
    parsed.threats.sort(key=lambda threat: SEVERITIES.index(threat.severity))
    findings = [
        Finding(
            rule="analyze-threats/design-threat",
            title=t.title,
            severity=t.severity,
            remediation=t.remediation,
            evidence=t.impact,
            locations=[
                {"kind": "file", "path": t.path, "start_line": t.line, "side": t.side}
            ],
        )
        for t in parsed.threats
        if t.change != "mitigated"
    ]
    details = Details(
        architecture=parsed.architecture,
        profile=selected,
        model=model,
        revision=head,
        base=base,
        included=len(docs),
        omitted=sum(gaps.values()),
        omission_reasons=gaps,
        open_questions=parsed.open_questions,
        threats=parsed.threats,
    )
    partial = bool(gaps or parsed.open_questions)
    return Result(
        status="partial" if partial else "ok",
        summary=f"{len(findings)} threat(s) reported for the reviewed source.",
        data=details.model_dump(),
        findings=findings,
        target=scope,
        diagnostics=[
            Diagnostic(
                code="incomplete_context",
                level="warning",
                message="Source was omitted or material questions remain.",
            )
        ]
        if partial
        else None,
    )
