# Write a tool

This guide is for the AppSec team that maintains the suite. It shows how to turn a tool into an appsec-cli command, test it, and ship it to development teams.

[Choose an approach](#choose-an-approach) · [One-file tool](#one-file-tool) · [Python adapter](#python-adapter) · [Plugin interface](#plugin-interface) · [Test and distribute](#test-and-distribute) · [Update an engine](#update-an-engine)

## Choose an approach

| Your tool | Approach | You write |
| --- | --- | --- |
| A Python package whose console script prints a JSON object | [One-file tool](#one-file-tool) | `modules/<name>/tool.toml` in this repository |
| Needs its own finding rules, several subcommands, or engine-specific exit codes | [Python adapter](#python-adapter) | A small Python package created by `appsec-cli tools new` |
| Not written in Python | [Python adapter](#python-adapter) that starts the executable | An adapter that ships or depends on the executable |
| Runs as a separate service | [Python adapter](#python-adapter) that calls its API | An API adapter |

Both approaches give the command the same help, tool list entry, disable switch, and JSON output as every other command. Neither changes the CLI core.

## One-file tool

Create `modules/<name>/tool.toml` in this repository. The directory name becomes the command:

```toml
# modules/repo-inventory/tool.toml
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

- The engine must exit with 0 and print one JSON object on stdout. appsec-cli shows it unchanged under `data`.
- Any other exit code ends the run with `tool_failed` and exit code 3.
- Each run is limited to 120 seconds and 8 MiB of output.
- Names use lowercase letters, digits, and hyphens. `tools` and `schema` are reserved, and a module cannot reuse the name of a bundled plugin.

To update the engine, change the pin in `tool.toml` and release the suite with a new version.

## Python adapter

Use the generator for anything a one-file tool cannot express. It creates an independent package with an entry point, an example handler, and a test:

```sh
appsec-cli tools new team-inventory --scenario data
appsec-cli tools new policy-check --scenario findings
appsec-cli tools new reports --scenario group
appsec-cli tools new score-wrapper --scenario external \
  --engine appsec-security-score==0.3.3 --binary security-score
```

| Scenario | Creates |
| --- | --- |
| `data` | A command that returns typed data under `data`. |
| `findings` | A command that returns findings. Supports `--fail-on` and SARIF output. |
| `group` | A tool with subcommands, starting with `reports summary`. |
| `external` | A wrapper that starts the console script of a pinned engine package and returns its JSON. |

`--directory` chooses where the project is created; the default is the current directory.

For `external`, `--engine` names the pinned package and `--binary` its console script. pip installs the engine into the same environment as the adapter. Adapt the argument list, the accepted exit codes, and the translation of the native output to your tool. The [security-score adapter](../plugins/security-score/src/appsec_plugin_security_score/commands.py) shows this for a tool that also reports partial results.

A tool written in another language can ship its executable as a resource in platform-specific wheels. The adapter resolves the resource from its installed package and starts it with `appsec_cli.external.invoke`. That function takes an argument list, uses no shell, and enforces a time and an output limit. For offline runs and reproducible upgrades, put the engine or its client in the adapter's pinned dependencies.

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

## Test and distribute

1. Adapt the generated handler and its test. Add team, source repository, and issue tracker to the package metadata. Keep a changelog of changes to commands and data contracts.
2. Build the wheel in a prepared Python build environment:

   ```sh
   python -m pip wheel --no-deps --no-build-isolation . -w dist
   ```

3. Install it into your appsec-cli installation and enable it:

   ```sh
   pipx inject appsec-cli dist/<wheel>.whl
   ```

   Then add the tool name under `[plugins].additional` in your [user configuration](../README.md#configuration).
4. Check `appsec-cli tools list --check`, `appsec-cli --format json tools describe NAME`, one real call, and one error case. Run the generated test with the Python of the environment where the adapter is installed:

   ```sh
   python -m unittest discover -s tests
   ```

5. To make it an official tool, publish the adapter wheel and its engine dependencies in your package index. In this repository's [pyproject.toml](../pyproject.toml), add the pinned adapter to `[tool.appsec-suite].dependencies` and its command name to `[tool.appsec-suite.bundle]`, then release the suite with a new version. Every team gets the tool with its next `pipx upgrade appsec-cli`.

A team can also keep a plugin of its own outside the suite. It installs the plugin with `pipx inject` and updates it with `pipx runpip appsec-cli install --upgrade appsec-plugin-NAME`.

After you add or rename an entry point, reinstall the package; entry points are read from the installed metadata.

## Update an engine

The engine can stay in its own repository with its own release cycle:

1. Release the new engine version.
2. In the adapter, raise the engine pin and the adapter version. Test how the adapter maps the new native output.
3. Release the suite with the new adapter pin and a new suite version.

For the engines of the example setup, also update the commit in [scripts/build_release.py](../scripts/build_release.py).

The offline adapter for AppSec Verifier contains no engine. It ships the report schema from Verifier commit `90fb9736af8911e0bb7e0d9b007328cfb86f9706` (Apache 2.0, license in the adapter). When the Verifier schema changes, update this file and check the exported fields against existing reports.
