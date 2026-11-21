"""Discover commands from installed distribution metadata, without importing plugins."""

from dataclasses import dataclass, field
from importlib import metadata
from .config import NAME
from .sdk import Command, ToolError


@dataclass
class Tool:
    name: str
    package: str
    version: str
    summary: str
    status: str
    commands: dict = field(default_factory=dict)

    def description(self):
        return dict(
            name=self.name,
            package=self.package,
            version=self.version,
            help=self.summary,
            status=self.status,
            commands=[
                self.name + (" " + c if c else "") for c in sorted(self.commands)
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
        except Exception:
            raise ToolError(
                "plugin_incompatible", f"Cannot load the command from {self.package}."
            ) from None


def discover(cfg):
    bundle = metadata.distribution("appsec-cli")
    names = {
        e.name for e in bundle.entry_points if e.group == "appsec_cli.bundle"
    } | cfg.additional
    tools = {}
    for name in sorted(names):
        if name in {"tools", "schema"} or not NAME.fullmatch(name):
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
        tools[name] = tool
    return tools
