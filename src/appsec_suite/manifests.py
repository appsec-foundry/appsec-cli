"""The same declarative module format is used at build time and at runtime."""

import re
from dataclasses import dataclass
from pathlib import Path

try:
    import tomllib
except ImportError:
    import tomli as tomllib

from packaging.requirements import Requirement
from packaging.version import Version


@dataclass(frozen=True)
class Manifest:
    name: str
    engine: Requirement
    args: tuple[str, ...]
    binary: str | None
    description: str

    @classmethod
    def read(cls, path: Path):
        name = path.parent.name
        if path.is_symlink() or path.parent.is_symlink() or not path.is_file():
            raise ValueError("Expected a regular module manifest")
        with path.open("rb") as stream:
            raw = stream.read(65537)
        if len(raw) > 65536:
            raise ValueError("Module manifest too large")
        doc = tomllib.loads(raw.decode("utf-8"))
        if not re.fullmatch(r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*", name) or name in {
            "tools",
            "schema",
        }:
            raise ValueError("Invalid module directory name")
        if doc.keys() - {"engine", "args", "binary", "description"} or not isinstance(
            doc.get("engine"), str
        ):
            raise ValueError(
                f"{name}: expected engine and optional args, binary or description"
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
        return cls(name, engine, tuple(args), binary, description)
