from appsec_cli import Finding, Result, command
from pydantic import BaseModel


class Summary(BaseModel):
    characters: int


@command(data=Summary, findings=True)
def run(text: str) -> Result:
    """Check the supplied text for unresolved TODO markers."""
    findings = []
    if "TODO" in text:
        findings.append(
            Finding(rule="template/todo", title="Unresolved TODO", severity="info")
        )
    return Result(
        summary=f"{len(findings)} finding(s).",
        data=Summary(characters=len(text)).model_dump(),
        findings=findings,
    )
