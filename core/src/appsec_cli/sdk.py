"""One decorator and a result envelope shared by every plugin."""

from dataclasses import dataclass
from typing import Any, Callable, Literal

from pydantic import BaseModel, ConfigDict, Field, JsonValue, TypeAdapter

Severity = Literal["critical", "high", "medium", "low", "info"]
SEVERITIES = ("critical", "high", "medium", "low", "info")


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, allow_inf_nan=False)


class Diagnostic(StrictModel):
    level: Literal["warning", "error", "info"]
    code: str
    message: str


class Finding(StrictModel):
    rule: str = Field(min_length=1)
    title: str = Field(min_length=1)
    severity: Severity
    locations: list[dict[str, JsonValue]] | None = None
    confidence: Literal["high", "medium", "low"] | None = None
    cwe: list[str] | None = None
    evidence: str | None = None
    remediation: str | None = None
    fingerprint: str | None = None


class Result(StrictModel):
    status: Literal["ok", "partial", "failed"] = "ok"
    summary: str = Field(min_length=1)
    target: dict[str, JsonValue] | None = None
    data: JsonValue | None = None
    findings: list[Finding] | None = None
    diagnostics: list[Diagnostic] | None = None


class Envelope(Result):
    schema_version: Literal[1]
    status: Literal["ok", "partial", "failed"]
    tool: str
    counts: dict[str, int] | None = None
    run: dict[str, JsonValue] | None = None


class ToolError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class Command:
    handler: Callable[..., Result]
    data_type: Any
    findings: bool
    fail_on: str | None
    engine_distribution: str | None = None
    render_data: Callable[[Any], list[str]] | None = None
    api_version: int = 1
    forward_except: tuple[str, ...] | None = None
    list_findings: bool = False
    engine_help: tuple[str, ...] | None = None

    @property
    def data_adapter(self):
        return TypeAdapter(self.data_type)


def command(
    *,
    data: Any = JsonValue,
    findings: bool = False,
    fail_on: str | None = None,
    engine_distribution: str | None = None,
    render_data: Callable[[Any], list[str]] | None = None,
    list_findings: bool = False,
    forward_except: tuple[str, ...] | None = None,
    engine_help: tuple[str, ...] | None = None,
):
    """Declare one typed command. Its signature becomes the CLI and its help.

    With forward_except, the command is a wrapper: it declares no arguments of
    its own, and everything after its name reaches the handler in ctx.args for
    the engine, except the listed engine options. engine_help is the console
    script and arguments that print the engine's help for --help.
    """
    if fail_on not in (None, "never", *SEVERITIES):
        raise ValueError("unknown severity threshold")

    def decorate(handler):
        return Command(
            handler,
            data,
            findings,
            fail_on,
            engine_distribution,
            render_data,
            forward_except=tuple(forward_except)
            if forward_except is not None
            else None,
            list_findings=list_findings,
            engine_help=tuple(engine_help) if engine_help else None,
        )

    return decorate
