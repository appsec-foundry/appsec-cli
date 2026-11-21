import hashlib
import json
import os
import tempfile
from collections import Counter
from pathlib import Path

from .sdk import Envelope, SEVERITIES, ToolError


def finalize(result, tool, spec, run, threshold, min_severity, limit):
    body = result.model_dump(exclude_none=True)
    if "data" in result.model_fields_set:
        parsed = spec.data_adapter.validate_python(result.data, strict=True)
        body["data"] = spec.data_adapter.dump_python(parsed, mode="json")
    report = Envelope(schema_version=1, tool=tool, run=run, **body).model_dump(
        exclude_none=True
    )
    if "data" in body:
        report["data"] = body["data"]
    code = 0 if result.status == "ok" else 3
    if result.findings is not None:
        if not spec.findings:
            raise ValueError("unexpected findings")
        rows = report["findings"]
        counts = Counter(item["severity"] for item in rows)
        report["counts"] = {k: counts[k] for k in SEVERITIES}
        for row in rows:
            if not row["rule"].startswith(tool + "/"):
                raise ValueError("wrong rule prefix")
            identity = [row["rule"], row.get("locations") or row["title"]]
            row.setdefault(
                "fingerprint",
                hashlib.sha256(
                    json.dumps(identity, sort_keys=True).encode()
                ).hexdigest(),
            )
        if (
            code == 0
            and threshold != "never"
            and any(counts[s] for s in SEVERITIES[: SEVERITIES.index(threshold) + 1])
        ):
            code = 1
        kept = [
            row
            for row in rows
            if SEVERITIES.index(row["severity"]) <= SEVERITIES.index(min_severity)
        ]
        report["findings"] = kept[:limit]
    return report, code


def sarif(result, unfiltered=()):
    levels = dict(
        critical="error", high="error", medium="warning", low="note", info="note"
    )
    scores = dict(critical="9.5", high="8.0", medium="5.5", low="3.0")
    rules, rows = {}, []
    for finding in unfiltered:
        rid, severity = finding.rule, finding.severity
        if rid not in rules or SEVERITIES.index(severity) < SEVERITIES.index(
            rules[rid]
        ):
            rules[rid] = severity
    for f in result.get("findings", []):
        rid, severity = f["rule"], f["severity"]
        row = {
            "ruleId": rid,
            "level": levels[severity],
            "message": {"text": f["title"]},
            "partialFingerprints": {"appsec/v1": f["fingerprint"]},
        }
        locations = []
        for loc in f.get("locations", []):
            if loc.get("kind") == "file" and isinstance(loc.get("path"), str):
                physical = {"artifactLocation": {"uri": loc["path"]}}
                if isinstance(loc.get("start_line"), int) and loc["start_line"] > 0:
                    physical["region"] = {"startLine": loc["start_line"]}
                locations.append({"physicalLocation": physical})
            else:
                locations.append(
                    {"logicalLocations": [{"name": json.dumps(loc, sort_keys=True)}]}
                )
        if locations:
            row["locations"] = locations
        rows.append(row)
    descriptors = [
        {
            "id": rid,
            **({"properties": {"security-severity": scores[s]}} if s in scores else {}),
        }
        for rid, s in rules.items()
    ]
    return {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": result["tool"], "rules": descriptors}},
                "invocations": [{"executionSuccessful": result["status"] == "ok"}],
                "results": rows,
            }
        ],
    }


def emit(value, path=None):
    text = (
        value
        if isinstance(value, str)
        else json.dumps(value, ensure_ascii=True, indent=2, allow_nan=False)
    )
    if path is None:
        print(text)
        return
    destination = Path(path)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=destination.parent, delete=False
        ) as f:
            temporary = Path(f.name)
            f.write(text + "\n")
        os.replace(temporary, destination)
    except OSError:
        raise ToolError("output_error", "Could not write the output file.") from None
    finally:
        if temporary:
            temporary.unlink(missing_ok=True)
