# JSON results and exit codes

This page is for CI pipelines, team CLIs, and coding agents that read appsec-cli results.

## Discover commands

- `appsec-cli schema` prints the common JSON Schema of a result, version 1.
- `appsec-cli --format json tools list` lists the suite `version` and the enabled tools with their version, `plugin_version` and command paths. `version` is the one a run reports as `tool_version`; `plugin_version` is the adapter's package version. It needs no model login.
- `appsec-cli --format json tools describe NAME` lists under `definitions` the parameters with their defaults, the output formats, and the `data_schema` of each command path.

## Result

Every result has `schema_version`, `tool`, `status`, and `summary`. Depending on the command, `target`, `run`, `data`, `findings`, `counts`, and `diagnostics` follow. A data-only result, for example from an inventory tool:

```json
{"schema_version":1,"tool":"team-inventory","status":"ok","summary":"Inventory complete.","data":{"components":12}}
```

| Field | Content |
| --- | --- |
| `schema_version` | Currently `1`. |
| `tool` | Command name. |
| `status` | `ok`, `partial`, or `failed`. Describes the run, not the security of the target. |
| `summary` | One sentence for people and coding agents. |
| `target` | What was checked, with a `kind` such as `repository`, `change`, `commit`, or `pull_request`. |
| `data` | The command's own result, any JSON value. Its schema is the command's `data_schema`. |
| `findings` | List of findings. An empty list means no findings. If the field is missing, the command does not report findings. |
| `counts` | Findings per severity before filtering. Present whenever `findings` is. |
| `diagnostics` | Errors and warnings, each with `level`, a fixed `code`, and `message`. |
| `run` | CLI, plugin, and tool version, start time, and duration of a completed run. For an adapter without an engine, the tool version is the adapter version. |

A finding has at least `rule`, `title`, and `severity` (`critical`, `high`, `medium`, `low`, `info`). Optional fields are `confidence`, `locations`, `cwe`, `evidence`, `remediation`, and `fingerprint`.

A compatible reader checks `schema_version`, reads the fields it knows, and ignores unknown fields and `kind` values. New optional fields keep the version. Removing, renaming, or redefining a field raises it.

## Exit codes

With `--format json` or `sarif`, every command ends with one of these codes. In the terminal, commands that show their engine's output, such as `security-score`, end with the engine's exit code instead.

| Exit | Meaning |
| --- | --- |
| 0 | Run complete, no finding at or above the threshold. |
| 1 | Run complete, threshold reached. |
| 2 | Usage error, explained on stderr. No result on stdout. |
| 3 | Run incomplete or failed; see `status` and `diagnostics`. |
| 130 | Cancelled by the user. |

Exit codes 0, 1, and 3 come with a result. With `--format json`, a result that ends with 1 names the threshold and the number of findings that reached it in the diagnostic `threshold_reached`. `--fail-on never` turns off the threshold, but incomplete and failed runs still end with 3.

A project's `.appsec-cli.toml` can only make the threshold stricter. A looser value is ignored and reported in `diagnostics` as `config_threshold_ignored`; any key other than a threshold stops the run with `config_forbidden_key`.

## Example tools

- `security-score` puts the score in `data.score` and `data.rating`. It reports the weaknesses its engine deducts points for as findings; observations the engine only marks for manual review are listed under `data.review` and don't count toward the threshold. It reports `partial` when the engine could not read all selected source, for example code in a language it does not support.
- `analyze-threats` reports `partial` when it left out source it was asked to review: a changed file of a commit or pull request, or any file of a repository review. Unchanged files left out of a change's context and the model's open questions are reported as diagnostics and under `data`. It fails with `llm_invalid_response` when the model's answer does not match the schema or cites no supplied file and line for a threat.
- `requirement-harvester run` returns the Harvester's summary unchanged under `data`: the number of `requirements` and `catalogs` and whether it was a `dry-run`. The catalog and the run report go to the paths in the Harvester's configuration. An invalid configuration ends with exit code 2. A failed sign-in, fetch, or export ends with 3 and `auth_failed`, `harvest_failed`, or `export_failed`.

## Filters and SARIF

`findings` lists the most severe first and keeps the tool's order within a severity. `--min-severity` and `--limit` shorten the printed finding list, so `--limit 5` keeps the five most severe findings. `counts` and the exit code are based on all findings.

Commands that report findings also support `--format sarif` (SARIF 2.1.0). For GitHub code scanning, each rule carries the highest severity of its findings as `security-severity`; rules with only `info` findings have none. Data-only commands reject SARIF with exit code 2.

Treat truncated or missing JSON output as a failed call, not as an empty result.
