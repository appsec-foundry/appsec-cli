"""Bounded subprocess I/O for the packaged engines and read-only source collection."""

import json
import os
import re
import selectors
import signal
import subprocess
import sysconfig
import time
from pathlib import Path

import click

from .sdk import ToolError

USAGE = re.compile(r"([\w.-]+(?: [\w.-]+)*): error: (.+)")


def engine(name):
    path = Path(sysconfig.get_path("scripts")) / name
    if not path.is_file():
        raise ToolError(
            "binary_not_found", f"The suite installation is missing {name}."
        )
    return str(path)


def invoke(
    argv,
    *,
    cwd=None,
    env=None,
    timeout=120,
    cap=8 * 1024 * 1024,
    stdin=None,
    stderr=None,
):
    """Run argv without a shell; return the exit code and stdout.

    stderr, a bytearray, receives the error output. The cap covers both streams.
    """
    try:
        proc = subprocess.Popen(
            argv,
            cwd=cwd,
            env=env,
            stdin=stdin or subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
    except OSError:
        raise ToolError(
            "binary_not_found", "The selected executable is unavailable."
        ) from None
    output = bytearray()
    total = 0
    deadline = time.monotonic() + timeout
    try:
        with selectors.DefaultSelector() as sel:
            for pipe in (proc.stdout, proc.stderr):
                sel.register(pipe, selectors.EVENT_READ)
            while sel.get_map():
                left = deadline - time.monotonic()
                if left <= 0:
                    raise subprocess.TimeoutExpired(argv[0], timeout)
                for key, _ in sel.select(left):
                    chunk = os.read(key.fileobj.fileno(), 65536)
                    if not chunk:
                        sel.unregister(key.fileobj)
                        continue
                    total += len(chunk)
                    if total > cap:
                        raise ToolError(
                            "output_too_large",
                            "Command output exceeded the configured limit.",
                        )
                    if key.fileobj is proc.stdout:
                        output.extend(chunk)
                    elif stderr is not None:
                        stderr.extend(chunk)
        code = proc.wait(timeout=max(0.01, deadline - time.monotonic()))
        return code, bytes(output)
    except subprocess.TimeoutExpired:
        raise ToolError("timeout", "The command exceeded its time limit.") from None
    finally:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        proc.wait()
        proc.stdout.close()
        proc.stderr.close()


def last_line(stderr):
    """The last line an engine wrote to stderr: usually why it stopped."""
    lines = bytes(stderr).decode(errors="replace").strip().splitlines()
    return lines[-1].strip() if lines else ""


def check_usage(code, out, stderr):
    """Raise a usage error when an argparse engine refused its arguments.

    argparse exits with 2, prints nothing on stdout and ends its error output
    with "PROG: error: REASON".
    """
    found = (
        USAGE.fullmatch(last_line(stderr)) if code == 2 and not out.strip() else None
    )
    if found:
        raise click.UsageError(
            f"{found[1]}: {found[2]}", click.get_current_context(silent=True)
        )


def json_object(raw):
    try:
        result = json.loads(raw)
        if not isinstance(result, dict):
            raise ValueError
        return result
    except (ValueError, RecursionError):
        raise ToolError(
            "invalid_tool_output", "The engine did not return a valid JSON object."
        ) from None


class ExternalTool:
    """Run a packaged executable that publishes JSON and a numeric version."""

    def __init__(self, binary, min_version=None, version_args=("--version",)):
        self.binary = binary
        self.min_version = min_version
        self.version_args = version_args

    def json(self, args, *, timeout=120, cap=8 * 1024 * 1024):
        import re
        from packaging.version import Version

        executable = engine(self.binary)
        if self.min_version:
            code, raw = invoke([executable, *self.version_args], cap=8192, timeout=10)
            version = re.search(rb"(?<![\w.])\d+(?:\.\d+)+(?![\w.])", raw)
            if (
                code
                or not version
                or Version(version[0].decode()) < Version(self.min_version)
            ):
                raise ToolError(
                    "binary_version_unsupported",
                    "The installed engine does not report a supported version.",
                )
        stderr = bytearray()
        code, raw = invoke([executable, *args], cap=cap, timeout=timeout, stderr=stderr)
        if code:
            check_usage(code, raw, stderr)
            raise ToolError(
                "tool_failed",
                last_line(stderr)
                or "The external engine could not complete the command.",
            )
        return json_object(raw)
