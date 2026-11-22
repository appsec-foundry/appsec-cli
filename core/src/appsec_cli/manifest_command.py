"""Adapt a packaged module definition to the public command contract."""

from dataclasses import dataclass
from importlib import metadata

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

    def wrapper(ctx: typer.Context):
        payload = ExternalTool(binary).json([*spec.args, *ctx.args])
        return Result(summary=f"{spec.name} completed.", data=payload)

    wrapper.__doc__ = spec.description
    return command(
        data=dict[str, JsonValue],
        engine_distribution=spec.engine.name,
        forward_except=spec.forward_except,
        engine_help=(binary, *spec.args, "--help"),
    )(wrapper)
