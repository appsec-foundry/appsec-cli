# GitLab CI

This guide is for the AppSec team that offers appsec-cli to projects on GitLab. The template [ci/gitlab/appsec-cli.yml](../ci/gitlab/appsec-cli.yml) installs a fixed release from your GitLab package registry, checks every package against its hash, and adds two jobs:

| Job | Runs | What it does |
| --- | --- | --- |
| `appsec-cli:changes` | In merge requests | `security-score` on the changes since the merge base. Findings at or above `APPSEC_CLI_FAIL_ON` fail the job. |
| `appsec-cli:score` | On the default branch | The score of the whole repository, as a report. Findings that exist already do not fail it. |

Both jobs print their JSON result in the job log and keep it under `appsec-cli/` as an artifact.

## Publish a release

In the GitLab project that holds your copy of appsec-cli:

1. Build and check the release with `make release-check`.
2. Upload the wheels from `dist/` and `.wheelhouse/` to the project's PyPI package registry, for example with twine.
3. Upload `dist/install.lock` as a generic package. It lists every package of an installation with its hash:

   ```sh
   curl --fail --header "JOB-TOKEN: ${CI_JOB_TOKEN}" --upload-file dist/install.lock \
     "${CI_API_V4_URL}/projects/${CI_PROJECT_ID}/packages/generic/appsec-cli/0.1.0/install.lock"
   ```

4. Tag the commit as `v0.1.0`. Projects include the template at this tag.

The jobs read the packages with the CI job token of the calling project. Add the groups or projects that use appsec-cli to the job token allowlist of your appsec-cli project.

## Use it in a project

```yaml
include:
  - project: appsec/appsec-cli
    ref: v0.1.0
    file: ci/gitlab/appsec-cli.yml

variables:
  APPSEC_CLI_VERSION: "0.1.0"
  APPSEC_CLI_PROJECT: "appsec%2Fappsec-cli"
  APPSEC_CLI_FAIL_ON: "high"
```

| Variable | Default | Meaning |
| --- | --- | --- |
| `APPSEC_CLI_VERSION` | `0.1.0` | The release to install. Keep it in step with `ref`. |
| `APPSEC_CLI_PROJECT` | `appsec%2Fappsec-cli` | The project with the package registry, as a numeric ID or a URL-encoded path. |
| `APPSEC_CLI_FAIL_ON` | `high` | The threshold of the merge request gate. |

## Limits

- A merge request can change `.gitlab-ci.yml` and remove these jobs. If the check must run for every merge request, start it from a pipeline your AppSec team controls, such as a pipeline execution policy, and require successful pipelines before merging.
- The release supports Linux x86_64 with Python 3.12, so the jobs use `python:3.12`, pinned by digest. Update the digest when you publish a release.
