"""Installation-owned plugin selection and project-scoped reporting defaults."""

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


@dataclass
class Settings:
    disabled: set[str] = field(default_factory=set)
    additional: set[str] = field(default_factory=set)
    thresholds: dict[str, str] = field(default_factory=dict)
    fail_on: str | None = None


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
    for doc, trusted in (
        (user, True),
        (read(Path(project or ".appsec-cli.toml"), required=bool(project)), False),
    ):
        allowed = {"tools", "fail_on", "plugins"} if trusted else {"tools", "fail_on"}
        if doc.keys() - allowed:
            raise ToolError(
                "config_forbidden_key",
                "This configuration contains an unsupported key.",
            )
        if "fail_on" in doc:
            result.fail_on = threshold(doc["fail_on"])
        tools = doc.get("tools", {})
        if not isinstance(tools, dict):
            raise ToolError("config_invalid", "Expected a table of tools.")
        for name, values in tools.items():
            if not isinstance(values, dict) or values.keys() - {"fail_on"}:
                raise ToolError(
                    "config_forbidden_key", "Only fail_on is supported in a tool table."
                )
            if "fail_on" in values:
                result.thresholds[name] = threshold(values["fail_on"])
    return result
