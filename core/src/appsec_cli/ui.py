"""Terminal output: a short frame around each tool's own view.

Around a tool's run, colour marks status and severity only, with the values of
AppSec Analyzer's palette, so a severity reads the same in every tool. Only the
start page, where no tool shows its own logo, carries the appsec-foundry logo in
slate. Off a terminal or with NO_COLOR, all text stays plain.
"""

import os
import sys
import unicodedata

from .sdk import SEVERITIES

# role -> (24-bit RGB, base-16 SGR)
PALETTE = {
    "ok": ((143, 209, 158), "32"),
    "warn": ((240, 198, 110), "33"),
    "critical": ((236, 109, 118), "31"),
    "high": ((239, 150, 109), "91"),
    "medium": ((240, 198, 110), "33"),
    "low": ((124, 196, 228), "36"),
    "info": ((109, 118, 134), "90"),
    "muted": ((109, 118, 134), "90"),
    "iris_rim": ((38, 46, 60), "90"),
    "iris": ((112, 128, 152), "37"),
    "iris_core": ((206, 214, 228), "97"),
    "iris_bracket": ((150, 160, 182), "37"),
}
NOTES = {"error": ("✗", "critical"), "warning": ("⚠", "warn"), "info": ("·", "muted")}
DATA_LINES = 40


def clean(value):
    """Untrusted text without control or format characters."""
    return "".join(
        c if c.isprintable() and unicodedata.category(c) != "Cf" else " "
        for c in str(value)
    )


class Style:
    """Colour for one output stream, or plain text."""

    def __init__(self, enabled=False, truecolor=False):
        self.enabled = enabled
        self.truecolor = enabled and truecolor

    @classmethod
    def detect(cls, off=False, stream=None, env=None):
        stream = sys.stdout if stream is None else stream
        env = os.environ if env is None else env
        if off or env.get("NO_COLOR"):
            enabled = False
        elif env.get("FORCE_COLOR", "") not in ("", "0"):
            enabled = True
        else:
            enabled = env.get("TERM") != "dumb" and stream.isatty()
        return cls(enabled, env.get("COLORTERM", "").lower() in ("truecolor", "24bit"))

    def _sgr(self, role):
        if role == "bold":
            return "1"
        rgb, base = PALETTE[role]
        return "38;2;{};{};{}".format(*rgb) if self.truecolor else base

    def __call__(self, text, *roles):
        if not self.enabled or not text or not roles:
            return text
        return f"\033[{';'.join(self._sgr(r) for r in roles)}m{text}\033[0m"

    def gradient(self, text, start, end):
        """Text blended from one role's colour to another's, per character."""
        if not self.truecolor or not text:
            return self(text, start)
        (r0, g0, b0), _ = PALETTE[start]
        (r1, g1, b1), _ = PALETTE[end]
        n = max(len(text) - 1, 1)
        parts = []
        for i, char in enumerate(text):
            rgb = (
                round(a + (b - a) * i / n) for a, b in ((r0, r1), (g0, g1), (b0, b1))
            )
            parts.append("\033[38;2;{};{};{}m{}".format(*rgb, char))
        return "".join(parts) + "\033[0m"


def logo(style, tagline, detail):
    """The three-line logo of the appsec-foundry tools, in slate, beside the name."""

    def rim(text):
        return style(text, "iris_rim")

    def bracket(text):
        return style(text, "iris_bracket")

    iris = style("█", "iris")
    top = rim("▄") + iris + rim("▄")
    middle = rim("█") + iris + style("█", "iris_core") + iris + rim("█")
    bottom = rim("▀") + iris + rim("▀")
    name = style(style.gradient("appsec-cli", "iris", "iris_core"), "bold")
    return [
        f"   {bracket('╭')}  {top}  {bracket('╮')}  {name}",
        f"   {bracket('│')} {middle} {bracket('│')}  {style(clean(tagline), 'muted')}",
        f"   {bracket('╰')}  {bottom}  {bracket('╯')}  {style(clean(detail), 'muted')}",
    ]


def overview(rows, style, version, tagline=""):
    """The start page: what the suite is, each command with an example, next steps."""
    count = f"{len(rows)} tool{'' if len(rows) == 1 else 's'}"
    reach = f"{count} · terminal, CI and coding agents"
    if style.enabled:
        lines = logo(style, tagline, f"{version} · {reach}")
    else:
        lines = [f"appsec-cli {version}", *([clean(tagline)] if tagline else []), reach]
    lines += ["", "Usage: appsec-cli [OPTIONS] TOOL [COMMAND] [ARGS]", ""]
    lines += [style("Tools", "bold"), *commands(rows, style)]
    lines += [
        "",
        style("Next steps", "bold"),
        *columns(
            [
                ("appsec-cli TOOL --help", "Arguments, options and examples of a tool"),
                ("appsec-cli tools list", "Installed tools, versions and status"),
                ("appsec-cli --format json TOOL", "Result as JSON for scripts and CI"),
                ("appsec-cli update", "Install the latest release"),
            ]
        ),
    ]
    return "\n".join(lines)


def commands(rows, style):
    """Each command with its summary and its first example."""
    entries = []
    for row in rows:
        status = "" if row["status"] == "unchecked" else f" [{clean(row['status'])}]"
        usage = row.get("usage") or [
            {"command": row["name"], "summary": row["help"], "examples": []}
        ]
        for number, item in enumerate(usage):
            entries.append((item, style(status, "muted") if number == 0 else ""))
    width = min(max((len(item["command"]) for item, _ in entries), default=0), 32)
    lines = []
    for item, status in entries:
        text = f"  {clean(item['command']):<{width}}  {clean(item['summary'])}"
        lines.append(text.rstrip() + status)
        if item["examples"]:
            lines.append("    " + style(clean(item["examples"][0]["run"]), "muted"))
    return lines


def example_lines(examples):
    """The examples of a help page: what each call does, then the call to copy."""
    lines = ["Examples:"]
    for item in examples:
        lines += [f"  # {clean(item['what'])}", f"  {clean(item['run'])}", ""]
    return lines[:-1]


def tool_list(rows, style):
    lines = [style("Tools", "bold")]
    for row in rows:
        status = "" if row["status"] == "unchecked" else f" [{row['status']}]"
        lines.append(
            f"  {row['name']:<20} {clean(row['version']):<10} "
            f"{clean(row['help'])}{style(status, 'muted')}"
        )
        for item in row.get("usage", []):
            command = item["command"].removeprefix(row["name"]).strip()
            summary = "" if item["summary"] == row["help"] else item["summary"]
            if command:
                lines.append(f"    {clean(command):<29} {clean(summary)}".rstrip())
    return "\n".join(lines)


def columns(rows):
    """Two aligned columns, such as options and their help."""
    rows = [(clean(a), clean(b)) for a, b in rows]
    width = min(max((len(a) for a, _ in rows), default=0), 32)
    return [f"  {a:<{width}}  {b}".rstrip() for a, b in rows]


def section(title, rows):
    return "\n".join([title, *columns(rows)])


def changes(data, style):
    """What an update changed: the suite, then added, removed and updated tools."""
    before, after = data["before"], data["after"]
    notes = [style("⚠ ", "warn") + clean(text) for text in data.get("warnings", [])]
    if before == after:
        return "\n".join(
            [f"appsec-cli {clean(after['version'])} is up to date.", *notes]
        )
    lines = [f"appsec-cli {clean(before['version'])} → {clean(after['version'])}"]
    old, new = before["tools"], after["tools"]
    for name in sorted(old.keys() | new.keys()):
        if name not in old:
            lines.append(style("  + ", "ok") + f"{clean(name)} {clean(new[name])}")
        elif name not in new:
            lines.append(style("  - ", "muted") + clean(name))
        elif old[name] != new[name]:
            lines.append(f"    {clean(name)} {clean(old[name])} → {clean(new[name])}")
    return "\n".join([*lines, *notes])


def describe(result, style):
    """Text form of 'tools describe': each command with its arguments."""
    head = f"{clean(result['name'])} {clean(result['version'])}"
    lines = [style(head, "bold"), clean(result["help"])]
    for command in result["definitions"]:
        rows = []
        for param in command["parameters"]:
            flag = param["options"][0]
            label = (
                ", ".join(param["options"]) if flag.startswith("-") else flag.upper()
            )
            if flag.startswith("-") and param["type"] != "boolean":
                label += " " + param["type"].upper()
            default = param.get("default")
            text = param["help"] or ""
            if default not in (None, False, ""):
                text += f" (default: {default})"
            rows.append((label, text.strip()))
        lines += ["", style("appsec-cli " + clean(command["command"]), "bold")]
        if command["help"]:
            lines.append("  " + clean(command["help"]))
        lines += columns(rows)
        if "forwards_except" in command:
            kept = ", ".join(command["forwards_except"])
            lines.append(
                "  Arguments go to the engine unchanged"
                + (f", except {clean(kept)}." if kept else ".")
            )
        lines.append(style("  Formats: " + ", ".join(command["formats"]), "muted"))
    return "\n".join(lines)


def table(
    result,
    style,
    render_data=None,
    *,
    threshold=None,
    code=3,
    verbose=False,
):
    """One header line, the tool's view, its notes and one outcome line."""
    lines = [header(result, style), "", style(clean(result["summary"]), "bold")]
    view = render_data(result["data"]) if render_data and "data" in result else None
    if view:
        lines += ["", *(clean(line) for line in view)]
    if "findings" in result and view is None:
        lines += findings(result, style)
    elif "data" in result and view is None:
        lines += ["", *data_lines(result["data"], style)]
    notes = [
        note(item, style, verbose)
        for item in result.get("diagnostics", [])
        if item["message"] != result["summary"]
    ]
    if notes:
        lines += ["", *notes]
    lines += ["", outcome(result, style, threshold, code)]
    return "\n".join(lines)


def header(result, style):
    tool = clean(result["tool"])
    if tool == "appsec-cli":
        return style(tool, "muted")
    version = result.get("run", {}).get("tool_version")
    target = result.get("target") or {}
    parts = [f"{tool} {clean(version)}" if version else tool]
    where = clean(target.get("url") or target.get("path") or "")
    if target.get("revision"):
        revision = clean(target["revision"])[:12]
        where = f"{where} @ {revision}" if where else revision
    if where:
        parts.append(where)
    return style("appsec-cli › " + " · ".join(parts), "muted")


def findings(result, style):
    counts = result.get("counts", {})
    total = sum(counts.values())
    if not total:
        return ["", "No findings."]
    rows = sorted(result["findings"], key=lambda f: SEVERITIES.index(f["severity"]))
    shown = f"showing {len(rows)} of {total}" if len(rows) < total else str(total)
    tally = " · ".join(
        style(f"{counts[s]} {s}", s) for s in SEVERITIES if counts.get(s)
    )
    lines = ["", f"{style('Findings', 'bold')} · {shown} · {tally}"]
    for number, item in enumerate(rows, 1):
        label = style(f"{item['severity'].upper():<8}", item["severity"])
        lines += ["", f"{number:>4}. {label} {clean(item['title'])}"]
        where = location(item.get("locations") or [])
        if where:
            lines.append("      " + where)
        if item.get("remediation"):
            lines.append(
                "      " + style("Fix: " + clean(item["remediation"]), "muted")
            )
    return lines


def location(locations):
    if not locations:
        return ""
    first = locations[0]
    keys = ("path", "url", "purl", "id", "ref")
    text = next(
        (str(first[k]) for k in keys if first.get(k)), str(first.get("kind", ""))
    )
    if isinstance(first.get("start_line"), int):
        text += f":{first['start_line']}"
    if len(locations) > 1:
        text += f" · +{len(locations) - 1} more"
    return clean(text)


def note(item, style, verbose):
    mark, role = NOTES[item["level"]]
    text = f"{style(mark, role)} {clean(item['message'])}"
    return text + style(f" ({clean(item['code'])})", "muted") if verbose else text


def outcome(result, style, threshold, code):
    if result["status"] == "failed":
        return style("✗", "critical") + " Failed (exit 3)"
    if result["status"] == "partial":
        return style("⚠", "warn") + " Incomplete (exit 3)"
    if code == 1:
        return style("✗", "critical") + f" Threshold {threshold} reached (exit 1)"
    if "findings" in result and threshold != "never":
        return style("✓", "ok") + f" No finding at or above {threshold} (exit 0)"
    return style("✓", "ok") + " Complete (exit 0)"


def data_lines(value, style, limit=DATA_LINES):
    """Readable lines for any JSON value, shortened to ``limit`` lines."""
    lines = []
    _walk(value, "", lines)
    if len(lines) <= limit:
        return lines
    more = f"… {len(lines) - limit} more lines. Use --format json for the full result."
    return lines[:limit] + [style(more, "muted")]


def _scalar(value):
    if value is None or value in ([], {}):
        return "-"
    if isinstance(value, bool):
        return "yes" if value else "no"
    return clean(value)


def _flat(item):
    return (
        isinstance(item, dict)
        and bool(item)
        and not any(isinstance(v, (dict, list)) for v in item.values())
    )


def _walk(value, pad, lines):
    if isinstance(value, dict):
        for key, item in value.items():
            if isinstance(item, (dict, list)) and item:
                lines.append(f"{pad}{clean(key)}:")
                _walk(item, pad + "  ", lines)
            else:
                lines.append(f"{pad}{clean(key)}: {_scalar(item)}")
    elif isinstance(value, list):
        if (
            value
            and all(_flat(i) for i in value)
            and len({tuple(i) for i in value}) == 1
        ):
            _columns(value, pad, lines)
            return
        for item in value:
            if isinstance(item, (dict, list)) and item:
                start = len(lines)
                _walk(item, pad + "  ", lines)
                lines[start] = pad + "- " + lines[start][len(pad) + 2 :]
            else:
                lines.append(f"{pad}- {_scalar(item)}")
    else:
        lines.append(pad + _scalar(value))


def _columns(rows, pad, lines):
    keys = list(rows[0])
    cells = [[clean(k) for k in keys], *([_scalar(r[k]) for k in keys] for r in rows)]
    widths = [max(len(row[i]) for row in cells) for i in range(len(keys))]
    for row in cells:
        lines.append(pad + "  ".join(c.ljust(w) for c, w in zip(row, widths)).rstrip())
