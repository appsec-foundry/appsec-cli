"""Adapt a packaged module definition to the public command contract."""

from dataclasses import dataclass
from importlib import metadata
from pathlib import Path
from typing import Annotated

import typer
from pydantic import JsonValue
from .external import ExternalTool
from .manifests import Manifest
from .sdk import Result, ToolError, command


@dataclass(frozen=True)
class ManifestEntry:
    spec: Manifest

    def load(self):
        return from_manifest(self.spec)


def from_manifest(spec):
    dist = metadata.distribution(spec.engine.name)
    scripts = {ep.name for ep in dist.entry_points if ep.group == "console_scripts"}
    binary = spec.binary or (
        next(iter(scripts)) if len(scripts) == 1 else spec.engine.name
    )
    if binary not in scripts or "/" in binary or "\\" in binary:
        raise ToolError(
            "binary_not_found",
            f"Select a console script provided by {spec.engine.name}.",
        )
    if not spec.engine.specifier.contains(dist.version, prereleases=True):
        raise ToolError(
            "binary_version_unsupported", f"This module requires {spec.engine}."
        )

    def execute(args):
        payload = ExternalTool(binary).json(args)
        return Result(summary=f"{spec.name} completed.", data=payload)

    def with_repo(
        repo: Annotated[
            Path,
            typer.Argument(help="Repository directory.", exists=True, file_okay=False),
        ] = Path("."),
    ):
        return execute(
            [str(repo.resolve()) if arg == "{repo}" else arg for arg in spec.args]
        )

    def without_repo():
        return execute(list(spec.args))

    handler = with_repo if "{repo}" in spec.args else without_repo
    handler.__doc__ = spec.description
    return command(data=dict[str, JsonValue], engine_distribution=spec.engine.name)(
        handler
    )
