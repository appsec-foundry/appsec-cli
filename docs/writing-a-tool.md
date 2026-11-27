# Write a tool

This guide is for the AppSec team that maintains the suite. Each tool is one directory in [tools/](../tools), and the directory name becomes the command. The release build finds every directory and pins its version; there is no list to maintain.

[Choose an approach](#choose-an-approach) · [One-file tool](#one-file-tool) · [Python adapter](#python-adapter) · [Engine sources](#engine-sources) · [Tools that are off by default](#tools-that-are-off-by-default) · [Descriptions and examples](#descriptions-and-examples) · [Plugin interface](#plugin-interface) · [Test a tool](#test-a-tool) · [Versions and updates](#versions-and-updates)

## Choose an approach

| Your tool | The directory contains |
| --- | --- |
| A Python package whose console script prints a JSON object | [`tool.toml`](#one-file-tool) only |
| Needs its own finding rules, several commands, or engine-specific exit codes | A [Python adapter](#python-adapter), copied from [tools/_template](../tools/_template) |
| Not written in Python, or runs as a separate service | A Python adapter that starts the program or calls its API |

Both kinds get the same help, tool list entry, disable switch, and JSON output as every other command, and neither needs a change to the CLI core.

- Names use lowercase letters, digits, and hyphens. `tools`, `schema`, and `update` are reserved, and two tools cannot share a name.
- A directory holds either `tool.toml` or `pyproject.toml`, not both.
- Directories whose name starts with `_`, such as `_template`, are not part of a release.

## One-file tool

Create `tools/<name>/tool.toml`:

```toml
# tools/repo-inventory/tool.toml
engine = "appsec-analyzer==0.1.0a0"
args = ["repo-profile", "--json"]
```

After the next suite release, teams run `appsec-cli repo-inventory .`. The build adds the engine as a pip dependency of the suite.

| Field | Required | Meaning |
| --- | --- | --- |
| `engine` | Yes | The engine package, pinned as `package==version`. |
| `args` | No | Arguments the engine always gets. Everything the user types after the tool name follows them unchanged. Default: `["--json"]`. |
| `binary` | No | The console script to start if the package has several. Default: its only console script, or the one named like the package. |
| `description` | No | One line for the tool list and the help. |
| `examples` | No | Example calls for the start page and the help. See [Descriptions and examples](#descriptions-and-examples). |
| `enabled` | No | `false` ships the tool turned off. See [Tools that are off by default](#tools-that-are-off-by-default). |
| `source` | No | The Git repository and commit the release builds the engine from. See [Engine sources](#engine-sources). |
| `forward_except` | No | Engine options appsec-cli does not pass on, for example a self-update or an option that starts another program. Their abbreviations are refused too. |

- The engine must exit with 0 and print one JSON object on stdout. appsec-cli shows it unchanged under `data`.
- Any other exit code ends the run with `tool_failed` and exit code 3. When the engine rejects its arguments the way argparse does (exit 2, `PROG: error: REASON` on stderr), the run ends as a usage error with exit code 2.
- `appsec-cli NAME --help` shows the engine's own `--help`.
- Each run is limited to 120 seconds and 8 MiB of output.

## Python adapter

Copy the template and give it the new name in four places. For a tool named `policy-check`:

1. Copy the directory:

   ```sh
   cp -r tools/_template tools/policy-check
   ```

2. Rename the module directory `src/appsec_plugin_template` to `src/appsec_plugin_policy_check`.
3. In `pyproject.toml`, set `name = "appsec-plugin-policy-check"`, a `description`, and the entry point `"policy-check" = "appsec_plugin_policy_check:run"`.
4. In the code and in `tests/test_plugin.py`, replace `appsec_plugin_template` with `appsec_plugin_policy_check`, and the rule prefix `template/` with `policy-check/`.

The build stops when the package name does not match the directory. `appsec-cli tools list --check` reports an entry point whose name does not match.

The template has one command that returns data and findings. For a tool with several commands, register one entry point per command, such as `"reports.summary"` and `"reports.export"`; teams then run `appsec-cli reports summary`.

To wrap an engine, add it to `dependencies` with a pinned version, for example `"appsec-security-score==0.3.3"`, and start its console script with `appsec_cli.external.invoke`: your fixed arguments first, then everything the user typed. Name the engine under `[tool.appsec-cli]` as `engine = "appsec-security-score"`, so that `tools list`, `--version` and each run report its version; the release build checks that it is a pinned dependency. Adapt the accepted exit codes and the mapping of the engine's output to your tool. [Wrap an engine](#wrap-an-engine) has the details, and [Engine sources](#engine-sources) explains where the release build gets the engine.

A tool written in another language can ship its executable as a resource in platform-specific wheels. The adapter finds the resource in its installed package and starts it with `appsec_cli.external.invoke`, which takes an argument list, uses no shell, and limits run time and output size. For offline runs and reproducible upgrades, put the engine or its client in the adapter's pinned dependencies.

## Engine sources

Every package of a release is pinned. An engine comes from one of two places:

- **A Git source in the tool's directory.** The build clones the repository, checks out the commit, and builds the engine wheel from it.
- **The lock file** [requirements-linux-py312.lock](../requirements-linux-py312.lock), for an engine published on PyPI. Add it with its wheel hash; `make release-check` audits it against PyPI.

A `tool.toml` names the source in a `[source]` table. The package is its `engine`:

```toml
# tools/repo-inventory/tool.toml
engine = "appsec-analyzer==0.1.0a0"
args = ["repo-profile", "--json"]

[source]
git = "https://github.com/appsec-foundry/appsec-analyzer.git"
commit = "165425abccc7ca9b3dddb04c8f7a080293b0023e"
```

An adapter names it in its `pyproject.toml`, together with the dependency it builds:

```toml
[tool.appsec-cli.source]
package = "appsec-security-score"
git = "https://github.com/appsec-foundry/appsec-tools.git"
commit = "1c5a9b21d570c7c5650f80de3c7a1fdd43932d82"
path = "security-score"
```

| Field | Required | Meaning |
| --- | --- | --- |
| `git` | Yes | The Git URL of the repository. |
| `commit` | Yes | The full commit hash. The build does not accept a branch or tag, so it always builds the reviewed code. |
| `path` | No | The directory of the engine's `pyproject.toml` in the repository. Default: `.` |
| `package` | Adapters only | The dependency the source builds. `dependencies` must pin it with `==`. |

- Tools that share an engine each name the same source. The build stops if two tools name different sources for one package.
- The build runs the engine's packaging code. Name only repositories you trust.
- To build from another Git server, such as an internal mirror, or from a local checkout without changing the tool, set `ENGINE_SOURCES` to `PACKAGE=URL` pairs, for example `make release-check ENGINE_SOURCES="appsec-security-score=/src/appsec-tools"`. The commit in the tool's directory still applies.

## Tools that are off by default

`enabled = false` in a `tool.toml`, or under `[tool.appsec-cli]` in an adapter's `pyproject.toml`, ships the tool with the release but leaves it off. `appsec-cli tools list --all` shows it as `disabled`. A team turns it on in its [user configuration](../README.md#configuration):

```toml
[plugins]
additional = ["policy-check"]
```

`disabled` takes precedence, and a project configuration cannot turn a tool on.

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
summary = "Export a saved assessment, for example as SARIF or HTML."
examples = [
  { run = "appsec-analyzer export --assessment ./assessment --output ./out", what = "Export a saved assessment" },
]
```

A `tool.toml` takes the same `examples` array.

- `run` is the call without `appsec-cli`. It starts with the tool name and, for a tool with several commands, with the command.
- `what` says in one line what the call does. The help prints it as a `#` comment above the call.
- Start the description and each `summary` with a verb, such as "Score a repository …" or "Export a saved assessment …".
- Say in the description or `summary` whether the tool calls a model.
- Each command has at most 5 examples. `run`, `what`, and `summary` are one line of up to 100 characters.
- The release build stops on an invalid entry or a command the tool does not have.
- A tool without entries appears with its name and description only. This also applies to plugins installed outside the suite with `pipx inject`.

## Plugin interface

A plugin registers its handler in the entry-point group `appsec_cli.tools`. The entry point `team-inventory` of the package `appsec-plugin-team-inventory` becomes `appsec-cli team-inventory`. A group registers one entry point per operation, such as `reports.summary` and `reports.export`. This lets the start page and `--format json tools list` show every command path without importing plugin code.

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
- `@command(data=...)` declares the schema of `data`, which `tools describe` publishes.
- `@command(findings=True)` allows findings. Every rule starts with the command name and a slash, such as `policy-check/todo`.
- A plugin sets `status` (`ok`, `partial`, `failed`) and can add `diagnostics` with fixed codes.
- In the terminal, appsec-cli shows a header line, the summary, the findings (or, for a data-only command, the data as `key: value` lines), and an outcome line. Before that, when the run starts, a line on stderr names the tool and its version; this also holds for a wrapper with `passthrough=`. To show the data differently, pass `render_data=` a function that turns the validated data into plain lines of text. The JSON output stays the same.
- Raise `typer.BadParameter` for invalid arguments (exit code 2) and `appsec_cli.ToolError(code, message)` for an expected failure (status `failed`, exit code 3).
- Plugins return a result and never print to stdout themselves.

### Wrap an engine

`forward_except=(...)` makes a command a wrapper. The command declares no arguments of its own; everything after its name reaches the handler in `ctx.args` (declare `ctx: typer.Context`). Start the engine with your fixed arguments followed by `ctx.args`.

In `forward_except`, list the engine options appsec-cli must not pass on: output formats the adapter cannot read, a self-update, and options that start another program or choose a secret or a destination for data. argparse engines accept abbreviated options, so appsec-cli refuses the abbreviations too.

- `engine_help=("console-script", "--help")` makes `--help` show the engine's help.
- `appsec_cli.external.check_usage(code, stdout, stderr)` turns an argparse rejection into a usage error.
- `appsec_cli.external.last_line(stderr)` returns the engine's reason when it stops. `invoke(..., stderr=buffer)` collects that output.

To let the engine answer in the terminal, set `passthrough=function`. With `--format table`, appsec-cli calls that function instead of the handler and runs the `appsec_cli.Passthrough(argv, env=...)` it returns on the caller's terminal. The engine's output and exit code are then the result, without header and outcome line, and appsec-cli refuses `--output`, `--fail-on`, `--min-severity`, `--limit`, and `APPSEC_CLI_FAIL_ON`. `--format json` and `sarif` still call the handler.

With a passthrough, list the output formats the handler cannot read in `json_except=(...)` instead of `forward_except`, so the terminal still accepts them. Build `env` the same way the handler does, for example without secrets the engine must not send.

An engine may run for 120 seconds. For longer runs, give `invoke` and `Passthrough` the same `timeout` in seconds.

The [security-score adapter](../tools/security-score/src/appsec_plugin_security_score/commands.py) shows all of this, including partial results.

## Test a tool

1. Adapt the template test. It calls the handler directly; the core tests already cover the CLI around it, such as help, usage errors, refused engine options, and exit codes. `make test` builds the checkout, installs it into `.venv/`, and runs it together with all other tests:

   ```sh
   make test
   ```

2. Build the wheel and add it to your installation:

   ```sh
   python -m pip wheel --no-deps --no-build-isolation tools/policy-check -w dist
   pipx inject appsec-cli dist/<wheel>.whl
   ```

   Until the tool is part of a release, enable it under `[plugins].additional` in your [user configuration](../README.md#configuration).
3. Check `appsec-cli tools list --check`, `appsec-cli --format json tools describe NAME`, one real call, and one error case.
4. `make release-check` builds the whole release with the new tool, runs the core tests and the tests in each `tools/NAME/tests`, installs the release with pipx, and checks every tool through the installed CLI.

After you add or rename an entry point, reinstall the package; entry points are read from the installed metadata.

A team can also keep a plugin outside the suite: copy the template into its own repository, publish the wheel in its package index, install it with `pipx inject appsec-cli appsec-plugin-NAME`, and enable it under `[plugins].additional`. `appsec-cli update` updates it together with the suite, as long as the package index has it.

## Versions and updates

Every tool shows one version: its engine's, from the pin of a `tool.toml` or the `engine` an adapter names, otherwise the package version of the adapter. `appsec-cli tools list`, `appsec-cli --version` and each run show it. The JSON of `tools list` and of a run also carries the adapter version as `plugin_version`. pip only installs a package again when its version changes, so:

1. **Engine update:** release the new engine first. Change the pin in `tool.toml`, or raise the pin and the version in the adapter's `pyproject.toml`. Test how the adapter maps the new native output.
2. **Adapter change:** raise the adapter version whenever anything in its directory changes. The same applies to the core in [core/](../core).
3. **Release:** raise the suite version in [pyproject.toml](../pyproject.toml), release, and tag the commit as `v<version>`. Teams get the change with `appsec-cli update`, which lists the new versions.

The release build stops when a package changed since the last `v*` tag without a new version, or when `v<version>` already points to another commit. In CI, fetch the tags with the checkout. For an engine with a Git source, also update `commit` in its [source](#engine-sources).

The AppSec Verifier adapter has no engine. It ships the report schema from [AppSec Verifier](https://github.com/appsec-foundry/appsec-verifier) commit `6c25aa17a2d81464dc3710a88967bb110cd9d9cd` under the Apache 2.0 license, with a copy in [tools/appsec-verifier/LICENSE](../tools/appsec-verifier/LICENSE). When the Verifier schema changes, replace the file and check the exported fields against existing reports.
