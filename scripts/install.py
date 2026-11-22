"""Build this checkout and install it with pipx, one line per step.

The steps run the commands of a plain build: a virtual environment with the
hash-checked dependencies, the release wheels from scripts/build_release.py, and
pipx without a package index. Their output goes to build/install.log, or to the
terminal with --verbose. URLs in it lose their user name and password first.
"""

import argparse
import os
import platform
import re
import shlex
import shutil
import subprocess
import sys
import threading
import time
from collections import deque
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VENV = ".venv/bin/python"
LOG = ROOT / "build/install.log"
WIDTH = 66
SPINNER = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
# role -> (24-bit RGB, base-16 SGR), the values of appsec_cli.ui.PALETTE
COLORS = {
    "ok": ((143, 209, 158), "32"),
    "error": ((236, 109, 118), "31"),
    "warn": ((240, 198, 110), "33"),
    "muted": ((109, 118, 134), "90"),
    "bold": (None, "1"),
}
CREDENTIALS = re.compile(r"\b([A-Za-z][A-Za-z0-9+.-]*://)[^/\s@]+@")
LOCK_NAME = re.compile(r"requirements-([a-z]+)-py(\d)(\d+)\.lock$")
ERROR_LINE = re.compile(r"\s*(error|fatal)\b", re.IGNORECASE)
UNREACHABLE = (
    "git cannot reach an engine repository. Check the network, or set"
    " ENGINE_SOURCES to a mirror you can reach."
)
# text in a failed command's output -> what to do about it
HINTS = (
    (
        "do not match the hashes",
        "A download does not match its hash in the lock file. Check the package"
        " index before you try again.",
    ),
    (
        "no matching distribution",
        "pip cannot reach the package index. Check the network or proxy.",
    ),
    (
        "terminal prompts disabled",
        "git needs credentials for an engine repository. Set up a credential"
        " helper or SSH key, or run make install VERBOSE=1 to enter them.",
    ),
    ("reference is not a tree", "The engine source lacks the pinned commit."),
    (
        "ensurepip is not available",
        "Python cannot create virtual environments. On Debian and Ubuntu:"
        " sudo apt install python3-venv",
    ),
    ("unable to access", UNREACHABLE),
    ("could not resolve host", UNREACHABLE),
)


class Failure(Exception):
    """A step that stopped, with what the user should see about it."""

    def __init__(self, summary, lines=()):
        super().__init__(summary)
        self.summary = summary
        self.lines = list(lines)


def redact(text):
    """Text without the user name and password of the URLs in it."""
    return CREDENTIALS.sub(r"\1***@", text)


def duration(seconds):
    whole = int(round(seconds))
    return f"{whole}s" if whole < 60 else f"{whole // 60}m {whole % 60:02d}s"


def plural(count, word):
    return f"{count} {word}{'' if count == 1 else 's'}"


def home(path):
    text = str(path)
    prefix = str(Path.home())
    return "~" + text[len(prefix) :] if text.startswith(prefix + os.sep) else text


def tool_version(tool):
    """The version a command reports, "" if it reports none, None if missing."""
    path = shutil.which(tool)
    if path is None:
        return None
    try:
        run = subprocess.run(
            [path, "--version"], capture_output=True, text=True, timeout=30
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    found = re.search(r"\d+(\.\d+)+", run.stdout)
    return found.group(0) if found else ""


def pipx_bin_dir():
    """Where pipx puts its commands; older pipx cannot report it."""
    try:
        run = subprocess.run(
            ["pipx", "environment", "--value", "PIPX_BIN_DIR"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if run.returncode == 0 and run.stdout.strip():
            return Path(run.stdout.strip())
    except (OSError, subprocess.SubprocessError):
        pass
    return Path(os.environ.get("PIPX_BIN_DIR") or Path.home() / ".local/bin")


def on_path(folder):
    entries = os.environ.get("PATH", "").split(os.pathsep)
    return any(
        Path(entry).expanduser().resolve() == folder.resolve()
        for entry in entries
        if entry
    )


def building(line):
    """What the release build works on, from a line of its output."""
    if line.startswith("Cloning into"):
        return "cloning an engine at its pinned commit"
    found = re.match(r"\s*Building wheel for (\S+)", line)
    return found.group(1) if found else None


class Screen:
    """Colour and a live progress line on a terminal, plain lines elsewhere."""

    def __init__(self, stream=None, env=None):
        self.stream = sys.stdout if stream is None else stream
        env = os.environ if env is None else env
        self.live = env.get("TERM") != "dumb" and self.stream.isatty()
        if env.get("NO_COLOR"):
            self.color = False
        else:
            self.color = self.live or env.get("FORCE_COLOR", "") not in ("", "0")
        self.truecolor = env.get("COLORTERM", "").lower() in ("truecolor", "24bit")
        self.width = shutil.get_terminal_size().columns or 80

    def paint(self, text, role):
        if not self.color or not text or role is None:
            return text
        rgb, base = COLORS[role]
        code = "38;2;{};{};{}".format(*rgb) if self.truecolor and rgb else base
        return f"\033[{code}m{text}\033[0m"

    def print(self, text=""):
        self.stream.write(text + "\n")
        self.stream.flush()

    def overwrite(self, text):
        self.stream.write("\r\033[2K" + text)
        self.stream.flush()

    def cursor(self, visible):
        if self.live:
            self.stream.write("\033[?25h" if visible else "\033[?25l")
            self.stream.flush()


class Installer:
    def __init__(self, args, screen, log=None):
        self.args = args
        self.screen = screen
        self.log_path = log
        self.log = None
        if log is not None:
            log.parent.mkdir(parents=True, exist_ok=True)
            self.log = log.open("w", encoding="utf-8")
            self.log.write(
                f"appsec-cli install log, {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
            )
        self.detail = ""
        self.tail = deque(maxlen=40)
        self.folder = None

    def close(self):
        if self.log is not None:
            self.log.close()

    def main(self):
        s = self.screen
        task = "build" if self.args.no_install else "install"
        s.print(
            s.paint("appsec-cli", "bold")
            + s.paint(f" · {task} from this checkout", "muted")
        )
        s.print()
        started = time.monotonic()
        steps = [
            ("Requirements", self.requirements),
            ("Dependencies", self.dependencies),
            ("Build", self.build),
        ]
        if not self.args.no_install:
            steps.append(("Install", self.install))
        for name, action in steps:
            if not self.step(name, action):
                return 1
        self.finish(time.monotonic() - started)
        return 0

    def step(self, name, action):
        """Run one step behind a spinner and print its result line."""
        if self.log is not None:
            self.log.write(f"\n== {name}\n")
        self.detail = ""
        self.tail.clear()
        started = time.monotonic()
        stop = threading.Event()
        spinner = None
        if self.screen.live and not self.args.verbose:
            self.screen.cursor(False)
            spinner = threading.Thread(
                target=self.spin, args=(name, started, stop), daemon=True
            )
            spinner.start()
        failure = None
        try:
            summary = action()
        except Failure as error:
            failure = error
        finally:
            stop.set()
            if spinner is not None:
                spinner.join()
                self.screen.overwrite("")
                self.screen.cursor(True)
        seconds = time.monotonic() - started
        if failure is not None:
            self.failed(name, failure, seconds)
            return False
        self.screen.print(self.row("✓", "ok", name, summary, seconds))
        return True

    def spin(self, name, started, stop):
        frame = 0
        while not stop.wait(0.08):
            mark = SPINNER[frame % len(SPINNER)]
            elapsed = time.monotonic() - started
            line = self.row(mark, None, name, self.detail, elapsed, fit=True)
            self.screen.overwrite(line)
            frame += 1

    def row(self, mark, role, name, detail, seconds, fit=False):
        """A step line; fit cuts the detail so a live line cannot wrap."""
        clock = duration(seconds) if seconds >= 1 else ""
        head = f"  {mark} {name:<15}"
        width = min(WIDTH, self.screen.width - 1)
        room = self.screen.width - 1 - len(head) - (len(clock) + 1 if clock else 0)
        if fit and len(detail) > room:
            detail = detail[: max(room - 1, 0)] + "…"
        text = f"  {self.screen.paint(mark, role)} {name:<15}{detail}"
        if clock:
            gap = max(width - len(head) - len(detail) - len(clock), 1)
            text += " " * gap + self.screen.paint(clock, "muted")
        return text

    def failed(self, name, failure, seconds):
        s = self.screen
        s.print(self.row("✗", "error", name, failure.summary, seconds))
        lines = failure.lines
        if not lines and not self.args.verbose:
            errors = [line for line in self.tail if ERROR_LINE.match(line)]
            lines = (errors or list(self.tail))[-6:]
        if lines:
            s.print()
            for line in lines:
                s.print("    " + line)
        output = "\n".join(self.tail).lower()
        hint = next((text for key, text in HINTS if key in output), None)
        if hint or (self.log_path and not failure.lines):
            s.print()
        if hint:
            s.print("  " + hint)
        if self.log_path and not failure.lines:
            s.print(s.paint(f"  Log: {os.path.relpath(self.log_path)}", "muted"))

    def finish(self, seconds):
        s = self.screen
        s.print()
        if self.args.no_install:
            s.print(f"Built in {duration(seconds)}. The wheels are in dist/.")
            return
        s.print(f"Installed in {duration(seconds)}.")
        if not on_path(self.folder):
            s.print()
            s.print(
                f"  {s.paint('⚠', 'warn')} {home(self.folder)} is not on your PATH.\n"
                "    Run pipx ensurepath, then open a new terminal."
            )
        s.print()
        s.print(s.paint("Get started", "bold"))
        for command, what in (
            ("appsec-cli", "Tools with an example call each"),
            ("appsec-cli TOOL --help", "Arguments, options and examples of a tool"),
        ):
            s.print(f"  {command:<24}{what}")
        if self.log_path:
            s.print()
            s.print(s.paint(f"Log: {os.path.relpath(self.log_path)}", "muted"))

    def announce(self, command):
        """Show a command the way make echoes it, without credentials."""
        line = redact(command)
        if self.log is not None:
            self.log.write(f"$ {line}\n")
        if self.args.verbose:
            self.screen.print(line)

    def run(self, command, detail, env=None, watch=None):
        """Run a command; return its output lines, raise Failure if it fails."""
        self.detail = detail
        self.tail.clear()
        extra = dict(env or {})
        self.announce(
            " ".join(
                [f"{key}={shlex.quote(value)}" for key, value in extra.items()]
                + [shlex.quote(str(part)) for part in command]
            )
        )
        environment = {**os.environ, **extra, "PYTHONUNBUFFERED": "1"}
        if not self.args.verbose:
            # A prompt would hide behind the progress line; fail with a hint.
            environment["GIT_TERMINAL_PROMPT"] = "0"
        try:
            process = subprocess.Popen(
                [str(part) for part in command],
                cwd=ROOT,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                errors="replace",
            )
        except OSError as error:
            raise Failure(f"{detail} failed", [f"{command[0]}: {error.strerror}"])
        lines = []
        with process:
            try:
                for raw in process.stdout:
                    line = redact(raw.rstrip())
                    lines.append(line)
                    if self.log is not None:
                        self.log.write(line + "\n")
                    if self.args.verbose:
                        self.screen.print(line)
                    if line.strip():
                        self.tail.append(line)
                    found = watch(line) if watch else None
                    if found:
                        self.detail = found
                code = process.wait()
            except BaseException:
                process.kill()
                raise
        if code != 0:
            raise Failure(f"{detail} failed")
        return lines

    def requirements(self):
        lock = self.args.lock
        found, missing = [], []
        named = LOCK_NAME.search(lock)
        system, need = "linux", (3, 10)
        if named:
            system, need = named.group(1), (int(named.group(2)), int(named.group(3)))
        wanted = "{}.{}".format(*need)
        if not sys.platform.startswith(system):
            missing.append(
                (system, f"{lock} holds packages for {system}, not {sys.platform}.")
            )
        if sys.version_info[:2] != need:
            missing.append(
                (
                    f"Python {wanted}",
                    f"{lock} holds packages for Python {wanted}; this is Python"
                    f" {platform.python_version()}."
                    f" Run: make install PYTHON=python{wanted}",
                )
            )
        else:
            found.append(f"Python {platform.python_version()}")
        tools = [("git", "git: install it with your package manager.")]
        if not self.args.no_install:
            tools.append(
                ("pipx", "pipx: install it as described at https://pipx.pypa.io")
            )
        for tool, how in tools:
            version = tool_version(tool)
            if version is None:
                missing.append((tool, how))
            else:
                found.append(f"{tool} {version}".strip())
        if missing:
            raise Failure(
                "needs " + ", ".join(name for name, _ in missing),
                [how for _, how in missing],
            )
        return " · ".join(found)

    def dependencies(self):
        lock, wheels = self.args.lock, self.args.wheels
        self.run([sys.executable, "-m", "venv", ".venv"], "creating .venv")
        self.run(
            [VENV, "-m", "pip", "download", "-q", "--only-binary=:all:"]
            + ["--require-hashes", "-r", lock, "-d", wheels],
            "downloading the pinned packages",
        )
        self.run(
            [VENV, "-m", "pip", "install", "-q", "--no-index", "--find-links", wheels]
            + ["--require-hashes", "-r", lock],
            "installing the build dependencies",
        )
        rows = (ROOT / lock).read_text().splitlines()
        count = sum(1 for row in rows if row[:1].isalnum())
        return f"{plural(count, 'package')}, hashes verified"

    def build(self):
        self.detail = "removing dist"
        self.announce("rm -rf dist")
        shutil.rmtree(ROOT / "dist", ignore_errors=True)
        command = [VENV, "scripts/build_release.py"]
        if self.args.release:
            command.append("--release")
        for pair in self.args.source:
            command += ["--source", pair]
        self.run(command, "building the wheels", watch=building)
        rows = (ROOT / "dist/release.lock").read_text().splitlines()
        names = [row.split("==")[0] for row in rows if row.strip()]
        engines = sum(
            1
            for name in names
            if name not in ("appsec_cli", "appsec_cli_core")
            and not name.startswith("appsec_plugin_")
        )
        built = plural(len(names) - engines, "package")
        if not engines:
            return built
        return f"{plural(engines, 'engine')} at pinned commits · {built}"

    def install(self):
        links = f"{ROOT / 'dist'} {ROOT / self.args.wheels}"
        self.run(
            [
                "pipx",
                "install",
                "--force",
                "--pip-args=--force-reinstall",
                "appsec-cli",
            ],
            "installing with pipx",
            env={"PIP_NO_INDEX": "1", "PIP_FIND_LINKS": links},
        )
        self.folder = pipx_bin_dir()
        lines = self.run(
            [self.folder / "appsec-cli", "--version"],
            "checking appsec-cli --version",
            env={"APPSEC_CLI_NO_UPDATE_CHECK": "1"},
        )
        version = next(
            (line.split()[1] for line in lines if re.match(r"appsec-cli \S+$", line)),
            "",
        )
        tools = [line for line in lines if re.match(r"\s+\S+\s+\S+$", line)]
        return f"appsec-cli {version} · {plural(len(tools), 'tool')}"


def parse(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--lock", required=True, help="Hash-pinned dependency lock")
    p.add_argument("--wheels", required=True, help="Directory for downloaded wheels")
    p.add_argument(
        "--source",
        action="append",
        default=[],
        metavar="PACKAGE=URL",
        help="Build an engine from another trusted Git URL or checkout",
    )
    p.add_argument(
        "--release", action="store_true", help="Pass --release to the release build"
    )
    p.add_argument(
        "--no-install", action="store_true", help="Build the wheels only, no pipx"
    )
    p.add_argument(
        "--verbose",
        action="store_true",
        help="Show every command and its output instead of the progress",
    )
    return p.parse_args(argv)


def main(argv=None):
    args = parse(argv)
    screen = Screen()
    installer = Installer(args, screen, None if args.verbose else LOG)
    try:
        return installer.main()
    except KeyboardInterrupt:
        screen.print()
        screen.print("Cancelled.")
        return 130
    finally:
        screen.cursor(True)
        installer.close()


if __name__ == "__main__":
    sys.exit(main())
