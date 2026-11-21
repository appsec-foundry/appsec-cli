"""Installation-owned plugin selection and finding thresholds.

The user configuration and a file chosen with --config are trusted. The
.appsec-cli.toml in the working directory may come from the reviewed change,
so it can make a threshold stricter but never looser.
"""

import os
from dataclasses import dataclass, field
from pathlib import Path

try:
    import tomllib
except ImportError:  # Python 3.10
    import tomli as tomllib

from .files import read_regular
from .manifests import NAME
from .sdk import SEVERITIES, ToolError


def strictness(value):
    """never < critical < high < medium < low < info."""
    return -1 if value == "never" else SEVERITIES.index(value)


@dataclass
class Settings:
    disabled: set[str] = field(default_factory=set)
    additional: set[str] = field(default_factory=set)
    # Thresholds per tool name; None holds the default for all tools.
    trusted: dict = field(default_factory=dict)
    local: dict = field(default_factory=dict)

    def threshold_for(self, tool, default):
        """The finding threshold of a tool, and whether a looser local one was ignored."""
        base = self.trusted.get(tool) or self.trusted.get(None) or default or "low"
        wanted = self.local.get(tool) or self.local.get(None)
        if wanted is None or strictness(wanted) >= strictness(base):
            return wanted or base, False
        return base, True


def read(path, *, required=False):
    try:
        raw = read_regular(path, 262144)
        return tomllib.loads(raw.decode("utf-8"))
    except FileNotFoundError:
        if not required:
            return {}
        raise ToolError(
            "config_missing", "The selected configuration file is missing."
        ) from None
    except (OSError, ValueError, RecursionError):
        raise ToolError(
            "config_invalid", "Cannot read the TOML configuration."
        ) from None


def threshold(value):
    if value not in ("never", *SEVERITIES):
        raise ToolError("config_invalid", "Unknown finding severity threshold.")
    return value


def settings(project=None):
    root = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config")
    result = Settings()
    user = read(root / "appsec-cli/config.toml")
    plugins = user.get("plugins", {})
    if not isinstance(plugins, dict) or plugins.keys() - {"disabled", "additional"}:
        raise ToolError("config_invalid", "Invalid plugin configuration.")
    for key in ("disabled", "additional"):
        names = plugins.get(key, [])
        if not isinstance(names, list) or not all(
            isinstance(n, str) and NAME.fullmatch(n) for n in names
        ):
            raise ToolError(
                "config_invalid", "Plugin names must be a list of command names."
            )
        setattr(result, key, set(names))
    result.trusted = thresholds(user, {"tools", "fail_on", "plugins"})
    local = read(Path(project or ".appsec-cli.toml"), required=bool(project))
    # A file chosen with --config is the caller's decision and counts as trusted.
    (result.trusted if project else result.local).update(
        thresholds(local, {"tools", "fail_on"})
    )
    return result


def thresholds(doc, allowed):
    """The thresholds of one file: None for its default, tool names for [tools.NAME]."""
    if doc.keys() - allowed:
        raise ToolError(
            "config_forbidden_key", "This configuration contains an unsupported key."
        )
    values = {None: threshold(doc["fail_on"])} if "fail_on" in doc else {}
    tools = doc.get("tools", {})
    if not isinstance(tools, dict):
        raise ToolError("config_invalid", "Expected a table of tools.")
    for name, table in tools.items():
        if not NAME.fullmatch(name):
            raise ToolError("config_invalid", "Name each tool table after a tool.")
        if not isinstance(table, dict) or table.keys() - {"fail_on"}:
            raise ToolError(
                "config_forbidden_key", "Only fail_on is supported in a tool table."
            )
        if "fail_on" in table:
            values[name] = threshold(table["fail_on"])
    return values
