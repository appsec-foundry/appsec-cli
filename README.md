# appsec-cli

[![Version](https://img.shields.io/badge/version-0.1.0-orange.svg)](pyproject.toml)
[![Status](https://img.shields.io/badge/status-alpha-orange.svg)](#appsec-cli)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](pyproject.toml)
[![SARIF](https://img.shields.io/badge/SARIF-v2.1.0-blue.svg)](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)

> [!NOTE]
> **Alpha.** Early version, actively developed. Tested on Linux x86_64 with Python 3.10 and Git.

appsec-cli lets an AppSec team give development teams its security tools as one command-line tool. Development teams install a single package and get every tool the AppSec team has released, with the same help, JSON output, and exit codes in the terminal, in CI pipelines, and for coding-agent skills. The AppSec team decides which tools and engine versions each release contains, and adds tools without changing the CLI core.

This repository ships an example setup with four tools from [appsec-foundry](https://github.com/appsec-foundry): a security score, a threat review, the AppSec Analyzer, and an export for AppSec Verifier reports. Replace or extend them with your own tools.

appsec-cli does not host a package index or run a service. Tools run locally on the developer's machine or the CI runner. In the example setup, only `analyze-threats` sends source code to a model provider; see [Model profiles and data use](#model-profiles-and-data-use).

[Quick start](#quick-start) · [How it works](#how-it-works) · [Example setup](#example-setup) · [For development teams](#for-development-teams) · [CI](#use-in-ci) · [Model profiles](#model-profiles-and-data-use) · [Add a tool](#add-your-own-tool) · [Release](#release-and-distribution) · [Configuration](#configuration) · [Documentation](#documentation)

## Quick start

These steps build the example setup and install it the way a development team would. You need Linux x86_64, Python 3.10, Git, [pipx](https://pipx.pypa.io/stable/), network access to PyPI, and read access to the appsec-foundry repositories.

1. **Get the sources.** The release build uses pinned commits of two engine repositories. Clone them next to this repository:

   ```sh
   git clone https://github.com/appsec-foundry/appsec-cli.git
   git clone https://github.com/appsec-foundry/appsec-tools.git
   git clone https://github.com/appsec-foundry/appsec-analyzer.git
   cd appsec-cli
   ```

2. **Build and check the release:**

   ```sh
   make release-check
   ```

   This checks the pinned dependencies against PyPI, builds the eight wheels of the suite in `dist/`, runs the tests, and tests a real pipx install and upgrade. It creates `.venv/` and `.wheelhouse/` in the checkout. If the engine checkouts are elsewhere, pass `SCORE_REPO=` and `ANALYZER_REPO=`. See [Release and distribution](#release-and-distribution).

3. **Install the suite** from the local wheels, as a development team would install it from your package index:

   ```sh
   PIP_NO_INDEX=1 PIP_FIND_LINKS="$PWD/dist $PWD/.wheelhouse" pipx install appsec-cli
   ```

4. **Try it:**

   ```sh
   appsec-cli                              # tools and usage
   appsec-cli tools list --check           # load every tool once
   appsec-cli security-score /path/to/app  # score a repository
   ```

5. **Hand it to your development teams.** Publish the wheels from `dist/` and `.wheelhouse/` in your team package index. Development teams then install and update with:

   ```sh
   pipx install appsec-cli
   appsec-cli update
   ```

## How it works

A release consists of four kinds of Python packages. pipx installs them together into one environment.

| Package | Role | Lives in |
| --- | --- | --- |
| `appsec-cli` (suite) | Contains one command per directory in [tools/](tools) and pins the exact versions of a release. Teams install this package. | This repository |
| `appsec-cli-core` | Help, tool discovery, configuration, output formats, and exit codes. | [core/](core) |
| `appsec-plugin-<tool>` (adapter) | Defines the command of one tool and translates the tool's output into the common result format. | `tools/<tool>/`, or its own repository |
| Engine | The actual tool, such as `appsec-security-score`. | Its own repository and release cycle |

**One tool is one directory.** `tools/<name>/tool.toml` wraps a tool that prints JSON, without any code. `tools/<name>/pyproject.toml` with its sources is a Python adapter. The release build finds both and pins their versions; there is no list to maintain.

The core lists tools from package metadata without importing them, so `appsec-cli` and `tools list` stay fast and keep working when one tool is broken. A tool is loaded only when it runs or is described. Adapters return a result object; the core prints it as text, JSON, or SARIF and computes the exit code.

## Example setup

The four tools of the example setup come from appsec-foundry. Each is a Python adapter in [tools/](tools).

| Command | What it does | Engine | Model calls |
| --- | --- | --- | --- |
| `security-score [REPO]` | Score and rating of a repository. With `--commit SHA` or `--staged`, the security relevance of a change. | [security-score](https://github.com/appsec-foundry/appsec-tools/tree/main/security-score) 0.3.3 | No |
| `analyze-threats [REPO]` | Threat review of the committed `HEAD`, of one commit (`--commit SHA`), or of a GitHub pull request (`--pr URL`). Reports architecture, threats with cited evidence, existing controls, and open questions. | [appsec-analyzer](https://github.com/appsec-foundry/appsec-analyzer) 0.1.0a0 | Yes |
| `appsec-analyzer repo-profile [REPO]` | Size, languages, and build manifests of a repository. | appsec-analyzer 0.1.0a0 | No |
| `appsec-analyzer export ASSESSMENT DESTINATION` | Converts a saved Analyzer assessment to SARIF (default) or HTML (`--format html`, needs Pandoc). | appsec-analyzer 0.1.0a0 | No |
| `appsec-verifier export VERIFICATION_YAML` | Validates a finished AppSec Verifier report and exports finding identities, verdicts, and confidence. | Report schema bundled in the adapter | No |

```sh
appsec-cli security-score .
appsec-cli analyze-threats --commit HEAD
appsec-cli analyze-threats --pr https://github.com/OWNER/REPO/pull/42
appsec-cli appsec-analyzer export ~/assessments/app ~/exports/app --format sarif
```

## For development teams

### Install and update

```sh
pipx install appsec-cli
appsec-cli update          # asks, runs pipx upgrade, shows what changed
appsec-cli --version       # suite and tool versions
```

Your AppSec team configures the package index. An update brings the tools and engine versions of the new release, including newly added tools, and lists added, removed, and updated tools. Tools you disabled stay disabled. In scripts, run `appsec-cli update --yes`; `pipx upgrade appsec-cli` does the same without the summary.

### Find commands

```sh
appsec-cli                           # tools and usage
appsec-cli tools list                # tools and their subcommands
appsec-cli tools list --all          # also disabled tools
appsec-cli tools describe NAME       # arguments, output formats, data schema
appsec-cli security-score --help     # help for one command
```

### Global options

Global options go **before** the tool name, the tool's own options after it:

```sh
appsec-cli --format json --output report.json security-score . --commit HEAD
```

| Option | Effect |
| --- | --- |
| `--format table\|json\|sarif` | Text for people (default), JSON for automation, or SARIF 2.1.0 for commands that report findings. |
| `--output FILE` | Write the result to a file instead of stdout. |
| `--fail-on SEVERITY` | End with exit code 1 when a finding reaches this severity: `critical`, `high`, `medium`, `low`, `info`, or `never`. |
| `--min-severity SEVERITY`, `--limit N` | Shorten the printed finding list. Counts and exit code still use all findings. |
| `--config FILE` | Use this project configuration instead of `.appsec-cli.toml`. See [Configuration](#configuration). |
| `--no-color`, `--verbose`, `--debug` | Control terminal output. |
| `--version` | Print the suite version. |

### Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Run complete, no finding at or above the threshold. |
| 1 | Run complete, at least one finding at or above the threshold. |
| 2 | Usage error, explained on stderr. |
| 3 | Run incomplete or failed; see `status` and `diagnostics` in the result. |
| 130 | Cancelled. |

The default threshold is `low`. Model-based tools such as `analyze-threats` default to `never`, so their findings alone never fail a run. [JSON results and exit codes](docs/result-schema.md) describes the result format.

### Disable a tool

Hide official tools you do not use in your user configuration:

```toml
# ~/.config/appsec-cli/config.toml
[plugins]
disabled = ["appsec-verifier"]
```

An empty list enables all official tools again. A disabled tool ends with exit code 2 before any of its code is loaded. A project configuration cannot change this selection.

## Use in CI

Run the command with an explicit threshold and keep the report even when the job fails:

```sh
appsec-cli --format json --output report.json --fail-on high security-score .
```

The exit code of this command is the job status. Save `report.json` as a job artifact in a step that also runs after a failure.

- **Set the threshold on the command line or with `--config`.** A `.appsec-cli.toml` in the working directory may set `fail_on`, and it overrides the runner's user configuration. In a pull request, the author controls that file and could lower the threshold. `--fail-on` and `--config FILE` take precedence over it.
- **For pull requests from forks,** pass a configuration from the trusted target branch, for example `--config /runner/trusted/appsec.toml`.
- **Exit code 3 means the check is incomplete or failed.** `security-score` reports `partial` when the engine could not cover all selected source, for example code in a language it does not read. A rating limited only by missing evidence of good controls is a complete run; the report notes it with the diagnostic `limited_evidence`. `analyze-threats` reports `partial` when it omitted source files or the model lists open questions. Read `status` and `diagnostics` to tell the cases apart.
- **Findings set the exit code, not the score.** A low score or the rating `Not assessed` alone ends with 0. To require a minimum score, check `data.score` or `data.rating` in the report.

### Call it from a team CLI

A team's own CLI can start appsec-cli with an argument list, read the JSON result, and pass on the exit code:

```python
import json
import subprocess
import sys

run = subprocess.run(
    ["appsec-cli", "--format", "json", "security-score", "."],
    capture_output=True, text=True,
)
if run.stdout and run.returncode in (0, 1, 3):
    report = json.loads(run.stdout)
    print(report["summary"])
if run.stderr:
    print(run.stderr, file=sys.stderr, end="")
sys.exit(run.returncode)
```

### Use it from a coding agent

The [usage skill](skills/appsec-cli/SKILL.md) lets a coding agent discover the enabled commands, read their data schema, run them with `--format json`, and report the result. The suite wheel also installs it in its environment under `share/appsec-cli/skills/appsec-cli/`.

## Model profiles and data use

> [!IMPORTANT]
> **`analyze-threats` sends source code to the selected model provider.** Check your organization's rules and the provider's data-handling terms before you analyze confidential code. The other commands of the example setup make no model calls.

`analyze-threats` uses Claude Code by default. Select another profile with `--profile`, or for all runs with `APPSEC_CLI_PROFILE`. `--model` and `APPSEC_CLI_MODEL` choose the model within the profile.

| Profile | Runtime | Requirement |
| --- | --- | --- |
| `claude` (default) | Claude Code | `claude` on the `PATH` with a working login |
| `codex-cli` | Codex CLI | `codex` on the `PATH` with a working login |
| `anthropic-api` | Anthropic Messages API | `ANTHROPIC_API_KEY` |
| `litellm` | OpenAI-compatible [LiteLLM](https://docs.litellm.ai/docs/simple_proxy) gateway | `LITELLM_BASE_URL` with an HTTPS address such as `https://gateway.example/v1`, `LITELLM_API_KEY`, and `--model` with a gateway alias that supports JSON schema output |

```sh
appsec-cli --format json analyze-threats --profile litellm --model team-review --commit HEAD
```

What the review sends and checks:

- It reads the committed Git objects of the selected revision, never uncommitted files. Changed files come first, then README, architecture, threat model, and requirements documents, then files next to the changes, then the rest of the repository.
- It sends at most 100 file versions, 32 KiB per file, and 160,000 bytes in total. It skips files that the Analyzer classifies as sensitive or binary and masks recognized secrets. The result counts every omitted file by reason.
- Profile, endpoint, and keys come from your environment, never from the analyzed repository.
- The model's answer must match a strict schema, and every threat must cite a supplied file and line. Otherwise the run fails with `llm_invalid_response`.
- A run without reported threats is not a security approval.

For a pull request in a private repository, provide a read token in `APPSEC_GIT_TOKEN` or `GIT_TOKEN`.

## Add your own tool

Add a directory to [tools/](tools). Its name becomes the command. Neither way changes the CLI core.

**A tool that prints JSON** needs one file:

```toml
# tools/repo-inventory/tool.toml
engine = "appsec-analyzer==0.1.0a0"
args = ["repo-profile", "{repo}", "--json"]
```

After the next suite release, teams run `appsec-cli repo-inventory .`. The build adds the engine as a dependency, and the engine's JSON appears unchanged under `data`.

**A tool with its own Python code**, for example for finding rules, several commands, or a custom output mapping, starts as a copy of [tools/_template](tools/_template):

```sh
cp -r tools/_template tools/policy-check
```

Then rename the package, its module, and its entry point to the new name. [Write a tool](docs/writing-a-tool.md) lists each step, the plugin interface, tests, and versions.

## Release and distribution

A suite release is a set of wheels with fixed versions. `make release-check` builds and checks it on a Linux x86_64 runner with Python 3.10, Git, and pipx:

```sh
make release-check SCORE_REPO=/path/to/appsec-tools ANALYZER_REPO=/path/to/appsec-analyzer
```

1. Checks every pinned external wheel against PyPI for its hash, yanked releases, and known advisories ([scripts/audit_lock.py](scripts/audit_lock.py)).
2. Creates `.venv/` and installs the external dependencies from [requirements-linux-py310.lock](requirements-linux-py310.lock) with hash checking.
3. Checks the versions (see below). Builds the engines from the commits pinned in [scripts/build_release.py](scripts/build_release.py), even when your engine checkouts are on another commit. Then builds the core, the adapters, and the suite. `dist/` then holds eight wheels and `release.lock` with their hashes.
4. Installs the release with hash checking and runs `pip check` and the contract tests.
5. Runs a real `pipx install` and `appsec-cli update` from a temporary local index ([tests/pipx_release.py](tests/pipx_release.py)).

The build runs the packaging code of the engine checkouts, so use trusted checkouts. To build without the checks in a prepared build environment, run `python3 scripts/build_release.py --score /path/to/appsec-tools --analyzer /path/to/appsec-analyzer`.

**Distribute** the wheels from `dist/` and `.wheelhouse/` through your team package index. `appsec-cli update` then updates all tools together and installs tools added since the last release. A command removed from the release disappears, even when pip leaves its old wheel in the environment.

**Versions.** The suite has one version in [pyproject.toml](pyproject.toml); each tool has its own: the engine pin of a `tool.toml`, or the package version of an adapter. pip only installs a package again when its version changes, so:

- Raise the suite version for every release, and tag the released commit as `v<version>`.
- Raise the version of an adapter, or of the core, whenever its directory changes.

The release build stops when `v<version>` already points to another commit, or when a package changed since the last `v*` tag without a new version. CI needs the tags for this check, so fetch them with the checkout.

To add an official tool, add its directory and raise the suite version. To update an engine, release the engine, raise its pin and the adapter version, then raise the suite version. For the engines of the example setup, also update the commit in [scripts/build_release.py](scripts/build_release.py).

## Configuration

| File | Location | Can set |
| --- | --- | --- |
| User configuration | `$XDG_CONFIG_HOME/appsec-cli/config.toml`, otherwise `~/.config/appsec-cli/config.toml` | Thresholds and the tool selection under `[plugins]` |
| Project configuration | `.appsec-cli.toml` in the current working directory, or the file passed with `--config` | Thresholds only |

```toml
fail_on = "high"                 # default threshold

[tools.security-score]
fail_on = "medium"               # threshold for one tool

[plugins]                        # user configuration only
disabled = ["appsec-verifier"]   # hide official tools
additional = ["team-inventory"]  # enable the separately installed appsec-plugin-team-inventory
```

The threshold comes from the first of these that is set: `--fail-on`, `APPSEC_CLI_FAIL_ON`, a `[tools.<name>]` entry, `fail_on`, the tool's own default, `low`. When both files set the same key, the project configuration wins.

A project configuration with any other key, such as `[plugins]`, an endpoint, or a path, stops the run with `config_forbidden_key`. A file passed with `--config` must exist. Configuration files never hold credentials; those come from the provider login or environment variables.

## Documentation

- [Write a tool](docs/writing-a-tool.md): one-file tools, Python adapters, tests, and distribution.
- [JSON results and exit codes](docs/result-schema.md): the result format for CI, team CLIs, and skills.
- [Usage skill](skills/appsec-cli/SKILL.md): instructions for coding agents.
- [Implementation plan](docs/implementation-plan.md) (German): design decisions and open acceptance items, for maintainers.

## Development

Run the contract tests in an environment where the suite is installed, for example the `.venv/` that `make release-check` creates:

```sh
.venv/bin/python -m unittest discover -s tests
```

Automated tests replace all model hosts with test doubles and make no model calls.
