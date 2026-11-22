# JSON results and exit codes

This page is for CI pipelines, team CLIs, and skills that read appsec-cli results.

## Discover commands

- `appsec-cli schema` prints the common JSON Schema of a result, version 1.
- `appsec-cli --format json tools list` lists the suite `version` and the enabled tools with their version and command paths. It needs no model login.
- `appsec-cli --format json tools describe NAME` lists under `definitions` the parameters with their defaults, the output formats, and the `data_schema` of each command path.

## Result

Every result has `schema_version`, `tool`, `status`, and `summary`. Depending on the command, `target`, `run`, `data`, `findings`, `counts`, and `diagnostics` follow. This inventory returns data only:

```json
{"schema_version":1,"tool":"team-inventory","status":"ok","summary":"Inventory complete.","data":{"components":12}}
```

| Field | Content |
| --- | --- |
| `schema_version` | Currently `1`. |
| `tool` | Command name. |
| `status` | `ok`, `partial`, or `failed`. Describes the run, not the security of the target. |
| `summary` | One sentence for people and skills. |
| `target` | What was checked, with a `kind` such as `repository`, `change`, `commit`, or `pull_request`. |
| `data` | The command's own result, any JSON value. Its schema is the command's `data_schema`. |
| `findings` | List of findings. An empty list means that no findings were found. A missing field means that the command makes no statement about findings. |
| `counts` | Findings per severity before filtering. Present whenever `findings` is. |
| `diagnostics` | Errors and warnings, each with `level`, a fixed `code`, and `message`. |
| `run` | CLI, plugin, and tool version, start time, and duration of a completed run. For an adapter without an engine, the tool version is the adapter version. |

A finding has at least `rule`, `title`, and `severity` (`critical`, `high`, `medium`, `low`, `info`). Optional fields are `confidence`, `locations`, `cwe`, `evidence`, `remediation`, and `fingerprint`.

A compatible reader checks `schema_version`, reads the fields it knows, and ignores unknown fields and `kind` values. New optional fields keep the version. Removing, renaming, or redefining a field raises it.

## Exit codes

| Exit | Meaning |
| --- | --- |
| 0 | Run complete, no finding at or above the threshold. |
| 1 | Run complete, threshold reached. |
| 2 | Usage error, explained on stderr. No result on stdout. |
| 3 | Run incomplete or failed; see `status` and `diagnostics`. |
| 130 | Cancelled by the user. |

Exit codes 0, 1, and 3 come with a result. `--fail-on never` turns off the threshold, but incomplete and failed runs still end with 3.

## Filters and SARIF

`findings` lists the most severe first and keeps the tool's order within a severity. `--min-severity` and `--limit` shorten the printed finding list, so `--limit 5` keeps the five most severe findings. `counts` and the exit code are based on all findings.

Commands that report findings also support `--format sarif` (SARIF 2.1.0). For GitHub code scanning, each rule carries the highest severity of its findings as `security-severity`; rules with only `info` findings have none. Data-only commands reject SARIF with exit code 2.

A truncated report or missing JSON output is an error of the call, not an empty result.
