"""The tool.toml format, read by the suite build and by the CLI at runtime.

Needs only the standard library and packaging, so the build loads it without
installing the core.
"""

import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

try:
    import tomllib
except ImportError:
    import tomli as tomllib

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name
from packaging.version import Version

NAME = re.compile(r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*\Z")
RESERVED = {"tools", "schema", "update"}
PACKAGE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?\Z")
COMMIT = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?\Z")
MAX_EXAMPLES = 5
MAX_LINE = 100


def line(value):
    """One printable line of text, such as a summary or an example."""
    return (
        isinstance(value, str)
        and 0 < len(value) <= MAX_LINE
        and value.strip() == value
        and value.isprintable()
    )


def examples(value, prefix):
    """Checked examples [{run, what}]; each run starts with the command it shows."""
    if value is None:
        return []
    if not isinstance(value, list) or len(value) > MAX_EXAMPLES:
        raise ValueError(f"{prefix}: give at most {MAX_EXAMPLES} examples as a list")
    for item in value:
        if (
            not isinstance(item, dict)
            or item.keys() != {"run", "what"}
            or not line(item["run"])
            or not line(item["what"])
        ):
            raise ValueError(f"{prefix}: an example is {{ run, what }}, each one line")
        if item["run"] != prefix and not item["run"].startswith(prefix + " "):
            raise ValueError(f"{prefix}: start each example with '{prefix}'")
    return [{"run": item["run"], "what": item["what"]} for item in value]


def usage(name, table, commands):
    """Summaries and examples of a tool's commands from [tool.appsec-cli].

    ``commands`` holds the tool's command names, "" for a tool with one command.
    """
    if not isinstance(table, dict) or table.keys() - {"examples", "commands"}:
        raise ValueError(f"{name}: [tool.appsec-cli] takes examples and commands")
    found = {}
    if "examples" in table:
        if "" not in commands:
            raise ValueError(
                f"{name}: put the examples under [tool.appsec-cli.commands.NAME]"
            )
        found[""] = {"summary": "", "examples": examples(table["examples"], name)}
    entries = table.get("commands", {})
    if not isinstance(entries, dict):
        raise ValueError(f"{name}: [tool.appsec-cli.commands] is a table")
    for command, entry in entries.items():
        where = f"{name} {command}"
        if not command or command not in commands:
            raise ValueError(f"{name}: there is no command '{command}'")
        if not isinstance(entry, dict) or entry.keys() - {"summary", "examples"}:
            raise ValueError(f"{where}: a command takes summary and examples")
        if "summary" in entry and not line(entry["summary"]):
            raise ValueError(f"{where}: the summary is one line")
        found[command] = {
            "summary": entry.get("summary", ""),
            "examples": examples(entry.get("examples"), where),
        }
    return found


def enabled(value, prefix):
    """Whether a release turns the tool on; false ships it for teams to enable."""
    if not isinstance(value, bool):
        raise ValueError(f"{prefix}: enabled is true or false")
    return value


@dataclass(frozen=True)
class Source:
    """The Git repository and commit the release build makes an engine wheel from."""

    package: str
    git: str
    commit: str
    path: str = "."


def source(value, prefix, package=None):
    """A checked source table. A tool.toml passes its engine; an adapter names it."""
    keys = {"git", "commit", "path"} | ({"package"} if package is None else set())
    if not isinstance(value, dict) or value.keys() - keys:
        raise ValueError(f"{prefix}: a source takes {', '.join(sorted(keys))}")
    package = value.get("package", package)
    git, commit, path = value.get("git"), value.get("commit"), value.get("path", ".")
    if not isinstance(package, str) or not PACKAGE.fullmatch(package):
        raise ValueError(f"{prefix}: name the engine package the source builds")
    if not line(git) or git.startswith("-"):
        raise ValueError(f"{prefix}: give the source as a Git URL")
    if not isinstance(commit, str) or not COMMIT.fullmatch(commit):
        raise ValueError(f"{prefix}: pin the source to a full commit hash")
    inside = line(path) and not PurePosixPath(path).is_absolute()
    if not inside or ".." in PurePosixPath(path).parts:
        raise ValueError(f"{prefix}: give the engine's path inside the repository")
    return Source(canonicalize_name(package), git, commit, path)


@dataclass(frozen=True)
class Manifest:
    name: str
    engine: Requirement
    args: tuple[str, ...]
    binary: str | None
    description: str
    examples: tuple = ()
    enabled: bool = True
    source: Source | None = None

    @property
    def version(self):
        return next(iter(self.engine.specifier)).version

    @classmethod
    def read(cls, path: Path):
        name = path.parent.name
        if path.is_symlink() or path.parent.is_symlink() or not path.is_file():
            raise ValueError("Expected a regular tool.toml file")
        with path.open("rb") as stream:
            raw = stream.read(65537)
        if len(raw) > 65536:
            raise ValueError("tool.toml too large")
        doc = tomllib.loads(raw.decode("utf-8"))
        if not NAME.fullmatch(name) or name in RESERVED:
            raise ValueError(f"{name}: invalid tool directory name")
        if doc.keys() - {
            "engine",
            "args",
            "binary",
            "description",
            "examples",
            "enabled",
            "source",
        } or not isinstance(doc.get("engine"), str):
            raise ValueError(
                f"{name}: expected engine and optional args, binary, description,"
                " examples, enabled or source"
            )
        engine = Requirement(doc["engine"])
        pins = list(engine.specifier)
        if (
            engine.url
            or engine.marker
            or engine.extras
            or len(pins) != 1
            or pins[0].operator != "=="
        ):
            raise ValueError(f"{name}: pin the engine as package==version")
        Version(pins[0].version)
        args = doc.get("args", ["{repo}", "--json"])
        if not isinstance(args, list) or not all(
            isinstance(arg, str) and "\0" not in arg for arg in args
        ):
            raise ValueError(f"{name}: args must be an array of strings")
        binary = doc.get("binary")
        if binary is not None and (
            not isinstance(binary, str)
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", binary)
        ):
            raise ValueError(f"{name}: binary must be a console script name")
        description = doc.get("description", f"Run {engine.name}.")
        if not isinstance(description, str) or not description.strip():
            raise ValueError(f"{name}: expected a description")
        found = tuple(examples(doc.get("examples"), name))
        on = enabled(doc.get("enabled", True), name)
        built = source(doc["source"], name, engine.name) if "source" in doc else None
        return cls(name, engine, tuple(args), binary, description, found, on, built)
