from pathlib import Path
from typing import Literal

from importlib.resources import files

import yaml
from jsonschema import Draft202012Validator
from pydantic import BaseModel, ConfigDict, Field
from appsec_cli.files import read_regular
from appsec_cli import Result, ToolError, command


class Reference(BaseModel):
    model_config = ConfigDict(strict=True)
    id: str = Field(min_length=1)
    match_key: str = Field(min_length=1)
    instance: str | None = None


class Row(BaseModel):
    finding_ref: Reference
    verdict: Literal[
        "confirmed",
        "not-reproducible",
        "blocked-by-control",
        "inconclusive",
        "not-attempted",
    ]
    confidence: Literal["high", "medium", "low"] | None = None


class Meta(BaseModel):
    schema_version: Literal[1]
    generated: str
    verifier_version: str
    source_assessment: str


class Report(BaseModel):
    meta: Meta
    results: list[Row]


class Annotation(BaseModel):
    finding_id: str
    match_key: str
    instance: str | None
    verdict: str
    confidence: str | None


class Export(BaseModel):
    meta: dict[str, str | int]
    annotations: list[Annotation]


@command(data=Export)
def export(verification: Path) -> Result:
    """Read a completed verification.yaml and export finding identities and verdicts."""
    try:
        raw = read_regular(verification, 8 * 1024 * 1024)
        # Reject aliases and executable/custom tags before constructing a report.
        depth = 0
        for count, event in enumerate(yaml.parse(raw, Loader=yaml.SafeLoader)):
            if isinstance(event, (yaml.MappingStartEvent, yaml.SequenceStartEvent)):
                depth += 1
            elif isinstance(event, (yaml.MappingEndEvent, yaml.SequenceEndEvent)):
                depth -= 1
            if depth > 60 or count > 160000:
                raise ValueError
            if isinstance(event, yaml.AliasEvent) or getattr(event, "tag", None):
                raise ValueError
        doc = yaml.safe_load(raw)
        if isinstance(doc, dict) and isinstance(doc.get("meta"), dict):
            from datetime import datetime

            if isinstance(doc["meta"].get("generated"), datetime):
                doc["meta"]["generated"] = doc["meta"]["generated"].isoformat()
        schema = yaml.safe_load(
            files(__package__).joinpath("verification.schema.yaml").read_text()
        )
        if not Draft202012Validator(schema).is_valid(doc):
            raise ValueError
        report = Report.model_validate(doc)
    except (ValueError, OSError, yaml.YAMLError, RecursionError):
        raise ToolError(
            "invalid_report",
            "Expected a readable verification.yaml with valid finding references and verdicts.",
        ) from None
    annotations = [
        Annotation(
            finding_id=row.finding_ref.id,
            match_key=row.finding_ref.match_key,
            instance=row.finding_ref.instance,
            verdict=row.verdict,
            confidence=row.confidence,
        )
        for row in report.results
    ]
    payload = Export(
        meta={
            "schema_version": 1,
            **report.meta.model_dump(),
            "verification_report": str(verification),
        },
        annotations=annotations,
    )
    return Result(
        summary=f"Exported {len(annotations)} verification annotations.",
        data=payload.model_dump(),
    )
