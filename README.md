# appsec-cli

[![Version](https://img.shields.io/badge/version-0.1.0-orange.svg)](pyproject.toml)
[![Status](https://img.shields.io/badge/status-alpha-orange.svg)](#appsec-cli)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](pyproject.toml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![SARIF](https://img.shields.io/badge/SARIF-v2.1.0-blue.svg)](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)

> [!NOTE]
> **Alpha.** Early version, actively developed. Tested on Linux x86_64 with Python 3.10 and Git.

appsec-cli bundles an AppSec team's security tools into one command-line tool for development teams. Developers install one package and get every tool in the release. All tools take the same global options, and with `--format json` they return the same result format and exit codes, so CI jobs and coding agents can call every tool the same way. The AppSec team decides which tools and engine versions go into a release. Adding a tool does not require changes to the CLI.

![Start page of appsec-cli in the terminal: the tools of the example setup with an example call each, and the next steps](docs/images/start-page.png)

This repository contains an example setup built on tools from [appsec-foundry](https://github.com/appsec-foundry): [Security Score](https://github.com/appsec-foundry/appsec-tools/tree/main/security-score), [AppSec Analyzer](https://github.com/appsec-foundry/appsec-analyzer), and [AppSec Verifier](https://github.com/appsec-foundry/appsec-verifier). Replace them with your own tools or add more.

appsec-cli has no server and no package index of its own. The tools run on the developer's machine or the CI runner. Of the example tools, only `analyze-threats` sends source code to a model provider; see [Data use](#model-profiles-and-data-use).

[Quick start](#quick-start) · [How it works](#how-it-works) · [Example setup](#example-setup) · [For development teams](#for-development-teams) · [CI](#use-in-ci) · [Data use](#model-profiles-and-data-use) · [Add a tool](#add-your-own-tool) · [Release](#release-and-distribution) · [Configuration](#configuration)

## Quick start

You need Linux x86_64, Python 3.10, Git, [pipx](https://pipx.pypa.io/stable/), access to PyPI, and read access to the appsec-foundry repositories on GitHub.

1. **Install the example setup:**

   ```sh
   git clone https://github.com/appsec-foundry/appsec-cli.git
   cd appsec-cli
   make install
   ```

   `make install` checks the prerequisites, builds the engines from their repositories at pinned commits, verifies the hashes of all other dependencies, and installs everything with pipx. It prints one line per step and writes the full output to `build/install.log`. Run it again after each `git pull`.

2. **Try it:**

   ```sh
   appsec-cli                              # tools with an example call each
   appsec-cli security-score /path/to/app  # score a repository
   ```

3. **Give it to your development teams.** Publish the release in your package index as described in [Release and distribution](#release-and-distribution). Developers then install it with `pipx install appsec-cli`.

## How it works

A release consists of Python packages that pipx installs into one environment:

| Package | Contents | Location |
| --- | --- | --- |
| `appsec-cli` | The suite that teams install. It pins the versions of all packages in a release. | This repository |
| `appsec-cli-core` | Help, tool discovery, configuration, output formats, and exit codes. | [core/](core) |
| `appsec-plugin-<tool>` | Adapter for one tool. Defines its command and converts its output into the common result format. | `tools/<tool>/` or its own repository |
| Engine | The tool itself, such as `appsec-security-score`. | Its own repository |

Each directory in [tools/](tools) is one tool. For a tool that prints JSON, a `tool.toml` is enough; a directory with a `pyproject.toml` is a Python adapter. The release build picks up both, so there is no list of tools to maintain. appsec-cli loads a tool's code only when the tool runs, so one broken tool does not affect the others.

## Example setup

The example tools come from appsec-foundry. Each one is a Python adapter in [tools/](tools).

| Command | What it does | Built on | Model calls |
| --- | --- | --- | --- |
| `security-score [REPO]` | Scores a local repository, or a GitHub or GitLab repository by its HTTPS URL. With `--commit SHA` or `--staged`, it rates how security-relevant a change is. `--details` adds area scores and a technology overview. | [Security Score](https://github.com/appsec-foundry/appsec-tools/tree/main/security-score) 0.3.3 | No |
| `analyze-threats [REPO]` | Threat review of `HEAD`, a commit (`--commit SHA`), or a GitHub pull request (`--pr URL`). Reports threats with cited evidence, existing controls, and open questions. | [AppSec Analyzer](https://github.com/appsec-foundry/appsec-analyzer) 0.1.0a0 | Yes |
| `appsec-analyzer repo-profile [REPO]` | Size, languages, and build manifests of a repository. | [AppSec Analyzer](https://github.com/appsec-foundry/appsec-analyzer) 0.1.0a0 | No |
| `appsec-analyzer export --assessment DIR --output DIR` | Converts a saved Analyzer assessment, for example to SARIF (`--formats sarif`) or HTML (`--formats html`, needs Pandoc). | [AppSec Analyzer](https://github.com/appsec-foundry/appsec-analyzer) 0.1.0a0 | No |
| `appsec-verifier export VERIFICATION_YAML` | Checks a finished AppSec Verifier report and exports its findings with verdict and confidence. | Report schema of [AppSec Verifier](https://github.com/appsec-foundry/appsec-verifier) | No |

```sh
appsec-cli security-score .
appsec-cli security-score https://github.com/OWNER/REPO
appsec-cli analyze-threats --pr https://github.com/OWNER/REPO/pull/42
appsec-cli appsec-analyzer export --assessment ~/assessments/app --output ~/exports/app --formats sarif
```

For a private repository on github.com or gitlab.com, `security-score` uses a read-only token from `GIT_TOKEN`. Other hosts don't receive it.

## For development teams

### Install and update

```sh
pipx install appsec-cli
appsec-cli update          # asks, upgrades, shows what changed
appsec-cli --version       # suite and tool versions
```

Your AppSec team provides the package index. `update` installs the latest release, including new tools, and lists what was added, removed, or updated. Plugins your team added with `pipx inject` are updated in the same run, and tools you disabled stay disabled. In scripts, use `appsec-cli update --yes`.

Once a day, appsec-cli checks for a newer release and prints a hint after the result. It only asks a package index other than PyPI that pip is configured with, and it skips the check in CI, in scripts without a terminal, and with `--format json` or `sarif`. Set `APPSEC_CLI_NO_UPDATE_CHECK=1` to turn it off.

### Find commands

```sh
appsec-cli                         # tools with an example call each
appsec-cli tools list              # tools and their subcommands
appsec-cli tools describe NAME     # arguments, output formats, data schema
appsec-cli security-score --help   # options and examples of one command
```

### Global options

Global options go before the tool name. Everything after the tool name belongs to the tool:

```sh
appsec-cli --format json --output report.json security-score . --commit HEAD
```

| Option | Effect |
| --- | --- |
| `--format table\|json\|sarif` | Text (default), JSON for automation, or SARIF 2.1.0 for commands that report findings. |
| `--output FILE` | Write the result to a file instead of stdout. |
| `--fail-on SEVERITY` | Exit with 1 when a finding reaches this severity: `critical`, `high`, `medium`, `low`, `info`, or `never`. |
| `--min-severity SEVERITY`, `--limit N` | Show fewer findings. Counts and exit code still include all of them. |
| `--config FILE` | Use this configuration instead of `.appsec-cli.toml`. See [Configuration](#configuration). |

`appsec-cli --help` lists all options.

### Tools that wrap an engine

`security-score` and the `appsec-analyzer` commands start an engine and pass everything after the tool name to it unchanged. `appsec-cli TOOL --help` shows the engine's own options:

```sh
appsec-cli security-score . --skip-checks JS-RANDOM --timeout 90
```

In the terminal, these commands show the engine's own output and end with its exit code. With `--format json` or `sarif`, appsec-cli reads the engine's result and returns the [common result](docs/result-schema.md) instead. `--output`, `--fail-on`, `--min-severity`, `--limit`, and `APPSEC_CLI_FAIL_ON` only work with the common result; in the terminal, appsec-cli refuses them with exit code 2. A `fail_on` from a configuration file also applies only to the common result.

appsec-cli refuses a few engine options with exit code 2: those that would replace the engine version of the release, start another program, or choose which secret the engine sends. With `--format json` or `sarif`, it also refuses options that change the engine's output, such as `--json`, `--yaml`, or `--quiet`.

`analyze-threats` and `appsec-verifier` run their own code and have their own options.

### Exit codes

With `--format json` or `sarif`, every command ends with one of these codes. `analyze-threats` and `appsec-verifier` also use them in the terminal.

| Code | Meaning |
| --- | --- |
| 0 | Run complete, no finding at or above the threshold. |
| 1 | Run complete, at least one finding at or above the threshold. |
| 2 | Usage error, explained on stderr. |
| 3 | Run incomplete or failed; see `status` and `diagnostics` in the result. |
| 130 | Cancelled. |

The default threshold is `low`. `analyze-threats` uses `never`, so its findings alone never fail a run. Details are in [JSON results and exit codes](docs/result-schema.md).

In the terminal, `security-score` and the `appsec-analyzer` commands end with their engine's own exit codes, which can mean something different. `security-score`, for example, ends with 1 when its assessment is incomplete and with 2 when some areas lack the evidence for a rating.

### Disable a tool

To hide official tools you don't use, list them in your user configuration:

```toml
# ~/.config/appsec-cli/config.toml
[plugins]
disabled = ["appsec-verifier"]
```

appsec-cli does not run or load a disabled tool. A project configuration cannot change this list.

## Use in CI

```sh
appsec-cli --format json --output report.json --fail-on high security-score .
```

The exit code is the job result. Keep `report.json` as a job artifact, even when the job fails. Always pass `--format json` or `sarif` in CI; otherwise `security-score` ends with its engine's exit code and appsec-cli refuses `--fail-on`.

Only findings decide the exit code, so a low score alone ends with 0. To require a minimum score, check `data.score` or `data.rating` in the report. `security-score` reports the weaknesses its engine deducts points for as findings. Observations the engine only marks for manual review are listed under `data.review` and don't count toward the threshold.

Exit code 3 means the check is incomplete or failed. `security-score` reports `partial` when the engine could not read all selected source, for example code in a language it does not support. `analyze-threats` reports `partial` when it left out source files or the model has open questions. `status` and `diagnostics` in the report say which case applies.

A `.appsec-cli.toml` in the checked-out repository may come from the change under review, so it can only make the threshold stricter. A looser value is ignored and reported as `config_threshold_ignored`. For pull requests from forks, pass a configuration from the trusted target branch with `--config`.

### Team CLIs and coding agents

Other programs, such as a team's own CLI, can call appsec-cli with `--format json` and read the result as described in [JSON results and exit codes](docs/result-schema.md).

The [usage skill](skills/appsec-cli/SKILL.md) tells coding agents how to find the enabled commands, run them with `--format json`, and report the result. The suite installs it under `share/appsec-cli/skills/appsec-cli/` in its environment.

## Model profiles and data use

> [!IMPORTANT]
> **`analyze-threats` sends source code to the selected model provider.** Check your organization's rules and the provider's data-handling terms before you analyze confidential code. The other example tools make no model calls.

`analyze-threats` uses Claude Code by default. Choose another profile with `--profile` or `APPSEC_CLI_PROFILE`, and the model with `--model` or `APPSEC_CLI_MODEL`.

| Profile | Runtime | Requires |
| --- | --- | --- |
| `claude` (default) | Claude Code | `claude` on the `PATH`, logged in |
| `codex-cli` | Codex CLI | `codex` on the `PATH`, logged in |
| `anthropic-api` | Anthropic Messages API | `ANTHROPIC_API_KEY` |
| `litellm` | OpenAI-compatible [LiteLLM](https://docs.litellm.ai/docs/simple_proxy) gateway | `LITELLM_BASE_URL` (HTTPS), `LITELLM_API_KEY`, and `--model` with a gateway alias that supports JSON schema output |

```sh
appsec-cli --format json analyze-threats --profile litellm --model team-review --commit HEAD
```

The review reads only committed files of the selected revision, never uncommitted changes. It sends at most 100 file versions, 32 KiB per file, and 160,000 bytes in total, changed files first. It skips files that the Analyzer classifies as sensitive or binary and masks recognized secrets. The result shows how many files were left out and why.

Profile, endpoint, and keys come from your environment, never from the analyzed repository. The model's answer must match a strict schema and cite a supplied file and line for every threat; otherwise the run fails with `llm_invalid_response`. A run without threats is not a security approval.

For a pull request in a private repository, set a read token in `APPSEC_GIT_TOKEN` or `GIT_TOKEN`.

## Add your own tool

Add a directory to [tools/](tools). Its name becomes the command, and the CLI core stays unchanged.

A tool that prints JSON needs only a `tool.toml`:

```toml
# tools/repo-inventory/tool.toml
engine = "appsec-analyzer==0.1.0a0"
args = ["repo-profile", "--json"]
```

After the next release, teams run `appsec-cli repo-inventory .` and get the engine's JSON unchanged under `data`.

For a tool with its own Python code, for example to map findings or to offer several commands, copy the template and rename the package, module, and entry point:

```sh
cp -r tools/_template tools/policy-check
```

[Write a tool](docs/writing-a-tool.md) explains each step, the plugin interface, and tests.

## Release and distribution

A release is a set of wheels with fixed versions. Build and check it on Linux x86_64 with Python 3.10, Git, and pipx:

```sh
make release-check
```

It audits the pinned dependencies against PyPI, builds the engines from the Git sources named in the tool directories, builds the core, adapters, and suite, and tests the result with a real `pipx install` and `appsec-cli update`. The wheels and `release.lock` with their hashes end up in `dist/`.

The example tools build their engines from GitHub. To build from another Git server, such as an internal GitLab, or from a local checkout, set `ENGINE_SOURCES` to pairs of engine package and Git URL or path. `make install` accepts the same variable:

```sh
make release-check ENGINE_SOURCES="\
  appsec-security-score=https://gitlab.example.com/appsec/appsec-tools.git \
  appsec-analyzer=https://gitlab.example.com/appsec/appsec-analyzer.git"
```

The source must contain the pinned commits; otherwise the build stops. The build runs the engines' packaging code, so use only sources you trust.

Upload the wheels from `dist/` and `.wheelhouse/` to your package index. `appsec-cli update` then brings the new release, including new tools, to every developer.

The package names are not registered on PyPI. Configure your index as pip's only source (`index-url`), not as an additional one (`extra-index-url`). Otherwise pip could install a package of the same name that someone else published on PyPI.

### Versions

pip only reinstalls a package when its version changes. Therefore:

- Raise the suite version in [pyproject.toml](pyproject.toml) for every release and tag the commit as `v<version>`.
- Raise the version of an adapter or of the core whenever something in its directory changes.

The release build stops if `v<version>` already points to another commit, or if a package changed since the last `v*` tag without a new version. In CI, fetch the tags with the checkout. [Write a tool](docs/writing-a-tool.md#versions-and-updates) describes how to update an engine.

## Configuration

| File | Location | Can set |
| --- | --- | --- |
| User configuration | `~/.config/appsec-cli/config.toml`, or under `$XDG_CONFIG_HOME` if set | Thresholds and the tool selection under `[plugins]` |
| Chosen configuration | The file passed with `--config` | Thresholds; overrides the user configuration key by key |
| Project configuration | `.appsec-cli.toml` in the working directory, if no `--config` is given | Stricter thresholds only |

```toml
fail_on = "high"                 # default threshold

[tools.security-score]
fail_on = "medium"               # threshold for one tool

[plugins]                        # user configuration only
disabled = ["appsec-verifier"]   # hide official tools
additional = ["team-inventory"]  # enable a tool that is off by default, or a separately installed one
```

The threshold comes from the first of these that is set: `--fail-on`, `APPSEC_CLI_FAIL_ON`, `[tools.<name>]`, `fail_on`, the tool's own default, `low`. A project configuration can then only make it stricter, for example `medium` instead of `high`. Any other key in a project configuration, such as `[plugins]`, an endpoint, or a path, stops the run with `config_forbidden_key`.

Credentials never go into configuration files. They come from the provider login or from environment variables.

## Documentation

- [Write a tool](docs/writing-a-tool.md): one-file tools, Python adapters, tests, and versions.
- [JSON results and exit codes](docs/result-schema.md): the result format for CI, team CLIs, and skills.
- [Usage skill](skills/appsec-cli/SKILL.md): instructions for coding agents.
- [Implementation plan](docs/implementation-plan.md) (German): design decisions, for maintainers.

## Development

Run the tests in an environment with the suite installed, for example the `.venv/` that `make release-check` creates:

```sh
.venv/bin/python -m unittest discover -s tests
```

The tests replace all model hosts with test doubles and make no model calls.

## License

appsec-cli is distributed under the [Apache 2.0 license](LICENSE). The tools in the example setup are separate projects with their own licenses.
