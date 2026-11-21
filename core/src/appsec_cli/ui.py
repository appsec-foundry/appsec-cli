"""Terminal hierarchy, status and colour conventions shared with AppSec Verifier."""

import json
import os
import sys
import unicodedata


def clean(value):
    return "".join(
        c if c.isprintable() and unicodedata.category(c) != "Cf" else " "
        for c in str(value)
    )


def color(text, code, off):
    enabled = (
        not off
        and not os.getenv("NO_COLOR")
        and (
            os.getenv("FORCE_COLOR") not in (None, "", "0")
            or (sys.stdout.isatty() and os.getenv("TERM") != "dumb")
        )
    )
    return f"\033[{code}m{text}\033[0m" if enabled else text


def overview(rows, off=False, *, full=False):
    title = color("appsec-cli", "1;95", off)
    head = [
        title,
        "Application security tools",
        "",
        "Usage: appsec-cli [OPTIONS] TOOL [COMMAND] [ARGS]",
        "",
        color("Tools", "1", off),
    ]
    if sys.stdout.isatty():
        head[:3] = [
            color("   ╭  ▄█▄  ╮  ", "35", off) + title,
            color("   │ █████ │  ", "91", off) + "Application security tools",
            color("   ╰  ▀█▀  ╯  ", "35", off) + f"{len(rows)} tools",
            "",
        ]
    for row in rows:
        suffix = f" [{row['status']}]" if row["status"] != "unchecked" else ""
        head.append(f"  {row['name']:<20} {clean(row['help'])}{suffix}")
        if full:
            head.extend(
                f"    {path}" for path in row["commands"] if path != row["name"]
            )
    head.extend(
        [
            "",
            color("Manage", "1", off),
            "  tools list [--all]       Installed tools and commands",
            "  tools describe TOOL      Help, arguments and data schemas",
            "  tools new NAME           Create a distributable plugin",
            "  schema                   Shared JSON result schema",
            "",
            color("Examples", "1", off),
            "  appsec-cli --format json tools list",
            "  appsec-cli tools new release-check --scenario findings",
        ]
    )
    return "\n".join(head)


def table(result, off, render_data=None):
    status = result["status"]
    label = {"ok": ("✓", "32"), "partial": ("⚠", "33"), "failed": ("✗", "31")}[status]
    lines = [
        color(f"{label[0]} {status}", label[1], off) + f"  {clean(result['tool'])}",
        clean(result["summary"]),
    ]
    for item in result.get("findings", []):
        lines.append(f"  {clean(item['severity']):<9} {clean(item['title'])}")
    for diagnostic in result.get("diagnostics", []):
        lines.append(f"  {clean(diagnostic['code'])}  {clean(diagnostic['message'])}")
    if "data" in result and render_data:
        lines.extend(clean(line) for line in render_data(result["data"]))
    elif "data" in result and not result.get("findings"):
        lines.append(json.dumps(result["data"], ensure_ascii=True, indent=2))
    return "\n".join(lines)
