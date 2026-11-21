# Write a tool

This guide is for the AppSec team that maintains the suite. Each tool is one directory in [tools/](../tools), and the directory name becomes the command. The release build finds every directory and pins its version; there is no list to maintain.

[Choose an approach](#choose-an-approach) · [One-file tool](#one-file-tool) · [Python adapter](#python-adapter) · [Descriptions and examples](#descriptions-and-examples) · [Plugin interface](#plugin-interface) · [Test a tool](#test-a-tool) · [Versions and updates](#versions-and-updates)

## Choose an approach

| Your tool | The directory contains |
| --- | --- |
| A Python package whose console script prints a JSON object | [`tool.toml`](#one-file-tool) only |
| Needs its own finding rules, several commands, or engine-specific exit codes | A [Python adapter](#python-adapter), copied from [tools/_template](../tools/_template) |
| Not written in Python, or runs as a separate service | A Python adapter that starts the program or calls its API |

Both kinds give the command the same help, tool list entry, disable switch, and JSON output as every other command. Neither changes the CLI core.

- Names use lowercase letters, digits, and hyphens. `tools`, `schema`, and `update` are reserved.
- A directory holds either `tool.toml` or `pyproject.toml`, not both.
- Directories whose name starts with `_`, such as `_template`, are not part of a release.

## One-file tool

Create `tools/<name>/tool.toml`:

```toml
# tools/repo-inventory/tool.toml
engine = "appsec-analyzer==0.1.0a0"
args = ["repo-profile", "{repo}", "--json"]
```

After the next suite release, teams run `appsec-cli repo-inventory .`. The build adds the engine as a pip dependency of the suite.

| Field | Required | Meaning |
| --- | --- | --- |
| `engine` | Yes | The engine package, pinned as `package==version`. |
| `args` | No | Arguments for the engine. Default: `["{repo}", "--json"]`. An element that is exactly `{repo}` becomes the absolute repository path. Without it, the command takes no repository argument. |
| `binary` | No | The console script to start if the package has several. Default: its only console script, or the one named like the package. |
| `description` | No | One line for the tool list and the help. |
| `examples` | No | Example calls for the start page and the help. See [Descriptions and examples](#descriptions-and-examples). |

- The engine must exit with 0 and print one JSON object on stdout. appsec-cli shows it unchanged under `data`.
- Any other exit code ends the run with `tool_failed` and exit code 3.
- Each run is limited to 120 seconds and 8 MiB of output.
- Names use lowercase letters, digits, and hyphens. `tools` and `schema` are reserved, and a module cannot reuse the name of a bundled plugin.

## Python adapter

Copy the template and give it the new name in four places. For a tool named `policy-check`:

1. Copy the directory:

   ```sh
   cp -r tools/_template tools/policy-check
   ```

2. Rename the module directory `src/appsec_plugin_template` to `src/appsec_plugin_policy_check`.
3. In `pyproject.toml`, set `name = "appsec-plugin-policy-check"`, a `description`, and the entry point `"policy-check" = "appsec_plugin_policy_check:run"`.
4. In the code and in `tests/test_plugin.py`, replace `appsec_plugin_template` with `appsec_plugin_policy_check`, and the rule prefix `template/` with `policy-check/`.

The build stops when the package name does not match the directory. `appsec-cli tools list --check` reports an entry point that does not.

The template has one command that returns data and findings. For a tool with several commands, register one entry point per command, such as `"reports.summary"` and `"reports.export"`; teams then run `appsec-cli reports summary`.

To wrap an engine, add it pinned to `dependencies`, for example `"appsec-security-score==0.3.3"`, and start its console script with `appsec_cli.external.ExternalTool` or `appsec_cli.external.invoke`. Adapt the argument list, the accepted exit codes, and the translation of the native output to your tool. The [security-score adapter](../tools/security-score/src/appsec_plugin_security_score/commands.py) shows this for a tool that also reports partial results.

A tool written in another language can ship its executable as a resource in platform-specific wheels. The adapter resolves the resource from its installed package and starts it with `appsec_cli.external.invoke`. That function takes an argument list, uses no shell, and enforces a time and an output limit. For offline runs and reproducible upgrades, put the engine or its client in the adapter's pinned dependencies.

## Descriptions and examples

The start page lists every command with a one-line description and its first example call. `appsec-cli TOOL --help` shows all examples of the tool. Both come from the tool's directory, so the CLI shows them without loading a tool.

In an adapter's `pyproject.toml`, a tool with one command lists its examples under `[tool.appsec-cli]`. Its description is the package `description`:

```toml
[tool.appsec-cli]
examples = [
  { run = "security-score .", what = "Score the current repository" },
  { run = "security-score --staged", what = "Check staged changes before you commit" },
]
```

A tool with several commands gives each command a `summary` and its `examples`:

```toml
[tool.appsec-cli.commands.export]
summary = "Export a saved assessment as SARIF or HTML."
examples = [
  { run = "appsec-analyzer export ./assessment ./out", what = "Export a saved assessment as SARIF" },
]
```

A `tool.toml` takes the same `examples` array.

- `run` is the call without `appsec-cli`. It starts with the tool name and, for a tool with several commands, with the command.
- `what` says in one line what the call does. The help prints it as a `#` comment above the call.
- Each command has at most 5 examples. `run`, `what`, and `summary` are one line of up to 100 characters.
- The release build stops on an invalid entry or a command the tool does not have.
- A tool without entries appears with its name and description only. This also applies to plugins installed outside the suite with `pipx inject`.

## Plugin interface

A plugin registers its handler in the entry-point group `appsec_cli.tools`. The entry point `team-inventory` of the package `appsec-plugin-team-inventory` becomes `appsec-cli team-inventory`. A group registers one entry point per operation, such as `reports.summary` and `reports.export`. This lets `tools list` show every command path without importing plugin code.

```python
from appsec_cli import Result, command
from pydantic import BaseModel


class Inventory(BaseModel):
    component: str


@command(data=Inventory)
def inspect(component: str) -> Result:
    """Report a selected component."""
    return Result(summary="Component inventoried.", data={"component": component})
```

- The handler's signature becomes the command's arguments and options, its docstring the help text.
- `@command(data=...)` declares the schema of `data`. `tools describe` publishes it.
- `@command(findings=True)` allows findings. Every rule starts with the command name and a slash, such as `policy-check/todo`.
- A plugin sets `status` (`ok`, `partial`, `failed`) and can add `diagnostics` with fixed codes.
- In the terminal, appsec-cli frames every command with one header line and one outcome line. In between it shows the summary, then the findings, or the data of a data-only command as `key: value` lines. `render_data=` replaces that view with your own: a function that turns the validated data into plain lines of text. The JSON output stays unchanged.
- Raise `typer.BadParameter` for invalid arguments (exit code 2) and `appsec_cli.ToolError(code, message)` for an expected failure (status `failed`, exit code 3).
- Plugins return a result and never print to stdout themselves.

## Test a tool

1. Adapt the template test and run it with the Python of an environment where the adapter is installed:

   ```sh
   python -m unittest discover -s tools/policy-check/tests
   ```

2. Build the wheel and add it to your installation:

   ```sh
   python -m pip wheel --no-deps --no-build-isolation tools/policy-check -w dist
   pipx inject appsec-cli dist/<wheel>.whl
   ```

   Until the tool is part of a release, enable it under `[plugins].additional` in your [user configuration](../README.md#configuration).
3. Check `appsec-cli tools list --check`, `appsec-cli --format json tools describe NAME`, one real call, and one error case.
4. `make release-check` builds the whole release with the new tool and runs the contract tests.

After you add or rename an entry point, reinstall the package; entry points are read from the installed metadata.

A team can also keep a plugin outside the suite: copy the template into its own repository, publish the wheel in its package index, install it with `pipx inject appsec-cli appsec-plugin-NAME`, and enable it under `[plugins].additional`. It updates with `pipx runpip appsec-cli install --upgrade appsec-plugin-NAME`.

## Versions and updates

Every tool has one version: the engine pin of a `tool.toml`, or the package version of an adapter. `appsec-cli tools list` and `appsec-cli --version` show it. pip only installs a package again when its version changes, so:

1. **Engine update:** release the new engine first. Change the pin in `tool.toml`, or raise the pin and the version in the adapter's `pyproject.toml`. Test how the adapter maps the new native output.
2. **Adapter change:** raise the adapter version whenever anything in its directory changes. The same applies to the core in [core/](../core).
3. **Release:** raise the suite version in [pyproject.toml](../pyproject.toml), release, and tag the commit as `v<version>`. Teams get the change with `appsec-cli update`, which lists the new versions.

The release build stops when a package changed since the last `v*` tag without a new version. For the engines of the example setup, also update the commit in [scripts/build_release.py](../scripts/build_release.py).

The offline adapter for AppSec Verifier contains no engine. It ships the report schema from Verifier commit `90fb9736af8911e0bb7e0d9b007328cfb86f9706` (Apache 2.0, license in the adapter). When the Verifier schema changes, update this file and check the exported fields against existing reports.
