"""Updates: a daily hint when the team's package index has a newer release."""

import json
import os
import re
import subprocess
import sys
import time
from importlib.metadata import version
from pathlib import Path
from urllib.parse import urlsplit

from packaging.version import InvalidVersion, Version

DAY = 24 * 60 * 60
PYPI = ("pypi.org", "pypi.python.org")


def pipx_metadata():
    """The pipx metadata of this installation, or None when pipx did not install it."""
    try:
        return json.loads((Path(sys.prefix) / "pipx_metadata.json").read_text())
    except (OSError, ValueError):
        return None


def run_pip(args, deadline):
    """stdout of a pip command in this environment, or None on failure or timeout."""
    try:
        proc = subprocess.Popen(
            [sys.executable, "-m", "pip", "--disable-pip-version-check", *args],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
    except OSError:
        return None
    try:
        out, _ = proc.communicate(timeout=max(0.0, deadline - time.monotonic()))
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.communicate()
        return None
    return out if proc.returncode == 0 else None


def team_index(settings):
    """Whether pip's configuration names an index other than PyPI."""
    for line in settings.splitlines():
        key, _, value = line.partition("=")
        option, value = key.rsplit(".", 1)[-1], value.strip().strip("'\"")
        if option == "index-url" and urlsplit(value).hostname not in PYPI:
            return True
        if option == "no-index" and value.lower() in ("1", "true", "yes", "on"):
            return True
    return False


def latest(limit=2.0):
    """The newest appsec-cli release in the team's package index, or None.

    pip answers with the index and login that 'appsec-cli update' uses. With
    nothing but PyPI configured there is no team release to look for.
    """
    deadline = time.monotonic() + limit
    settings = run_pip(["--no-input", "config", "list"], deadline)
    if not settings or not team_index(settings):
        return None
    listing = run_pip(["--no-input", "index", "versions", "appsec-cli"], deadline)
    found = re.match(r"appsec-cli \(([^()\s]+)\)", listing or "")
    return found[1] if found else None


def cache_path():
    base = os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache"
    return Path(base, "appsec-cli", "update-check.json")


def hint(now=None):
    """The line that points to a newer release, or None. Looks at most once a day."""
    if os.environ.get("APPSEC_CLI_NO_UPDATE_CHECK") or pipx_metadata() is None:
        return None
    now = time.time() if now is None else now
    path = cache_path()
    try:
        last = json.loads(path.read_text()).get("checked")
        if isinstance(last, (int, float)) and 0 <= now - last < DAY:
            return None
    except (OSError, ValueError, AttributeError):
        pass
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"checked": now}))
    except OSError:
        return None  # without a record of the last look, never look on every run
    newest = latest()
    try:
        if newest and Version(newest) > Version(version("appsec-cli")):
            return f"appsec-cli {newest} is available. Run 'appsec-cli update'."
    except InvalidVersion:
        pass
    return None
