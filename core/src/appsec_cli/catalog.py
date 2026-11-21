"""Discover commands from installed distribution metadata, without importing plugins."""

import json
from dataclasses import dataclass, field
from importlib import metadata, resources
from pathlib import Path
from .manifests import NAME, RESERVED, Manifest, usage
from .sdk import Command, ToolError


@dataclass
class Tool:
    name: str
    package: str
    version: str
    summary: str
    status: str
    commands: dict = field(default_factory=dict)
    usage: dict = field(default_factory=dict)

    def examples(self, command):
        """The examples of one command, as complete calls."""
        return [
            {"run": "appsec-cli " + item["run"], "what": item["what"]}
            for item in self.usage.get(command, {}).get("examples", [])
        ]

    def description(self):
        paths = {c: self.name + (" " + c if c else "") for c in sorted(self.commands)}
        return dict(
            name=self.name,
            package=self.package,
            version=self.version,
            help=self.summary,
            status=self.status,
            commands=list(paths.values()),
            usage=[
                {
                    "command": path,
                    "summary": self.usage.get(c, {}).get("summary")
                    or ("" if len(paths) > 1 else self.summary),
                    "examples": self.examples(c),
                }
                for c, path in paths.items()
            ],
        )

    def load(self, subcommand):
        if self.status != "unchecked":
            raise ToolError("tool_" + self.status, f"{self.name} is {self.status}.")
        try:
            spec = self.commands[subcommand].load()
            if not isinstance(spec, Command) or spec.api_version != 1:
                raise ValueError
            return spec
        except ToolError:
            raise
        except Exception:
            raise ToolError(
                "plugin_incompatible", f"Cannot load the command from {self.package}."
            ) from None


def collected():
    """The summaries and examples the suite build collected from its adapters."""
    try:
        text = resources.files("appsec_suite").joinpath("usage.json").read_text("utf-8")
        tables = json.loads(text)
    except (OSError, ValueError, ModuleNotFoundError):
        return {}
    return tables if isinstance(tables, dict) else {}


def discover(cfg):
    bundle = metadata.distribution("appsec-cli")
    tables = collected()
    names = {
        e.name for e in bundle.entry_points if e.group == "appsec_cli.bundle"
    } | cfg.additional
    tools = {}
    for name in sorted(names):
        if name in RESERVED or not NAME.fullmatch(name):
            raise ToolError(
                "plugin_conflict",
                "A plugin name conflicts with the CLI command catalog.",
            )
        package = "appsec-plugin-" + name
        try:
            dist = metadata.distribution(package)
        except metadata.PackageNotFoundError:
            tools[name] = Tool(
                name, package, "", "", "disabled" if name in cfg.disabled else "missing"
            )
            continue
        tool = Tool(
            name,
            package,
            dist.version,
            dist.metadata.get("Summary", ""),
            "disabled" if name in cfg.disabled else "unchecked",
        )
        for entry in dist.entry_points:
            if entry.group != "appsec_cli.tools":
                continue
            root, _, subcommand = entry.name.partition(".")
            if (
                root != name
                or (subcommand and not NAME.fullmatch(subcommand))
                or subcommand in tool.commands
            ):
                if tool.status != "disabled":
                    tool.status = "invalid"
                continue
            tool.commands[subcommand] = entry
        if tool.status == "unchecked" and (
            not tool.commands or ("" in tool.commands and len(tool.commands) > 1)
        ):
            tool.status = "invalid"
        if name in tables:
            try:
                tool.usage = usage(name, tables[name], tool.commands)
            except ValueError:
                pass  # The tool still runs; only its summaries and examples are missing.
        tools[name] = tool
    for manifest_entry in bundle.entry_points:
        if manifest_entry.group != "appsec_cli.manifests":
            continue
        name = manifest_entry.name
        if not NAME.fullmatch(name) or name in RESERVED:
            raise ToolError(
                "plugin_conflict", "Invalid tool name in the suite catalog."
            )
        if name in tools and tools[name].status not in {"missing", "disabled"}:
            raise ToolError("plugin_conflict", f"Duplicate command name: {name}.")
        status = "disabled" if name in cfg.disabled else "unchecked"
        summary, version, entry, examples = f"Run {name}.", "", None, ()
        if status != "disabled":
            from .manifest_command import ManifestEntry

            try:
                folder = Path(str(resources.files(manifest_entry.value)))
                manifest = Manifest.read(folder / name / "tool.toml")
                summary, version = manifest.description, manifest.version
                entry, examples = ManifestEntry(manifest), manifest.examples
            except (OSError, ValueError, ModuleNotFoundError):
                status = "invalid"
        tools[name] = Tool(
            name,
            "appsec-cli",
            version,
            summary,
            status,
            {"": entry},
            {"": {"summary": "", "examples": list(examples)}} if examples else {},
        )
    return dict(sorted(tools.items()))
