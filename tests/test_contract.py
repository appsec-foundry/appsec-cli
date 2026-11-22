"""Run against an installed suite with python -m unittest discover -s tests."""

import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import nullcontext, redirect_stderr
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import jsonschema
from appsec_cli import Finding, Result, ToolError, command
from appsec_cli.config import settings
from appsec_cli.external import invoke
from appsec_cli.output import finalize, sarif
from appsec_cli.sdk import Envelope
from appsec_plugin_appsec_verifier.commands import export
from appsec_plugin_security_score import commands as security_score
from appsec_plugin_analyze_threats import commands, hosts
from appsec_analyzer.engine import initialize


class Contracts(unittest.TestCase):
    def test_data_only_and_rules(self):
        @command(data=int)
        def number():
            return Result(summary="Score", data=45)

        report, code = finalize(number.handler(), "score", number, {}, "low", "high", 0)
        jsonschema.validate(report, Envelope.model_json_schema())
        self.assertEqual(code, 0)
        self.assertNotIn("findings", report)
        self.assertEqual(report["data"], 45)

        @command(findings=True)
        def scan():
            return Result(
                summary="Completed",
                findings=[
                    Finding(rule="test/x", title=s, severity=s)
                    for s in ("info", "high")
                ],
            )

        result = scan.handler()
        report, code = finalize(result, "test", scan, {}, "high", "info", 1)
        self.assertEqual(code, 1)
        self.assertEqual(report["counts"]["high"], 1)
        run = sarif(report, result.findings)["runs"][0]
        self.assertEqual(run["results"][0]["level"], "error")  # limit 1 keeps high
        self.assertEqual(
            run["tool"]["driver"]["rules"][0]["properties"]["security-severity"], "8.0"
        )

    def test_limit_keeps_the_most_severe_findings(self):
        @command(findings=True)
        def scan():
            return Result(
                summary="Completed",
                findings=[
                    Finding(rule="test/x", title=f"{s} {n}", severity=s)
                    for n, s in enumerate(("low", "high", "medium", "high"))
                ],
            )

        report, _ = finalize(scan.handler(), "test", scan, {}, "high", "info", 2)
        self.assertEqual([f["title"] for f in report["findings"]], ["high 1", "high 3"])
        report, _ = finalize(scan.handler(), "test", scan, {}, "high", "info", None)
        self.assertEqual(
            [f["title"] for f in report["findings"]],
            ["high 1", "high 3", "medium 2", "low 0"],
        )
        self.assertEqual(report["counts"]["high"], 2)

    def test_update_hint(self):
        from importlib.metadata import version

        from appsec_cli import updates

        newer = "appsec-cli 9.0.0 is available. Run 'appsec-cli update'."
        with (
            tempfile.TemporaryDirectory() as tmp,
            patch.dict(os.environ, {"XDG_CACHE_HOME": tmp}),
            patch.object(updates, "pipx_metadata", return_value={}),
            patch.object(updates, "latest", return_value="9.0.0") as look,
        ):
            self.assertEqual(updates.hint(now=1000.0), newer)
            self.assertIsNone(updates.hint(now=1000.0 + 3600))  # once a day
            self.assertEqual(look.call_count, 1)
            self.assertEqual(updates.hint(now=1000.0 + updates.DAY), newer)
            look.return_value = version("appsec-cli")
            self.assertIsNone(updates.hint(now=1000.0 + 2 * updates.DAY))
            look.return_value = None  # index unreachable or not configured
            self.assertIsNone(updates.hint(now=1000.0 + 3 * updates.DAY))
            with patch.dict(os.environ, {"APPSEC_CLI_NO_UPDATE_CHECK": "1"}):
                self.assertIsNone(updates.hint(now=1000.0 + 4 * updates.DAY))
            self.assertEqual(look.call_count, 4)
        with (
            patch.object(updates, "pipx_metadata", return_value=None),
            patch.object(updates, "latest") as look,
        ):
            self.assertIsNone(updates.hint())
            look.assert_not_called()

    def test_update_hint_asks_only_a_team_index(self):
        from appsec_cli import updates

        self.assertTrue(
            updates.team_index("global.index-url='https://pkgs.example.com/simple'")
        )
        self.assertTrue(updates.team_index(":env:.no-index='1'"))
        self.assertFalse(
            updates.team_index("global.index-url='https://pypi.org/simple'")
        )
        self.assertFalse(updates.team_index("global.timeout='5'"))
        listing = "appsec-cli (0.2.0)\nAvailable versions: 0.2.0, 0.1.0\n"
        for config, expected, asked in [
            ("global.index-url='https://pkgs.example.com/simple'\n", "0.2.0", True),
            ("", None, False),
            (None, None, False),
        ]:
            calls = []

            def pip(args, deadline):
                calls.append(args[1])
                return config if args[1] == "config" else listing

            with self.subTest(config=config), patch.object(updates, "run_pip", pip):
                self.assertEqual(updates.latest(), expected)
                self.assertEqual("index" in calls, asked)

    def test_bounded_process(self):
        literal = "; $(example)"
        self.assertEqual(
            invoke([sys.executable, "-c", "import sys;print(sys.argv[1])", literal])[
                1
            ].strip(),
            literal.encode(),
        )
        for src, kwargs, diagnostic in [
            ("print('x'*100)", {"cap": 20}, "output_too_large"),
            ("import time;time.sleep(5)", {"timeout": 0.1}, "timeout"),
        ]:
            with self.assertRaises(ToolError) as exc:
                invoke([sys.executable, "-c", src], **kwargs)
            self.assertEqual(exc.exception.code, diagnostic)

    def test_external_engine_version_and_output(self):
        from appsec_cli.external import ExternalTool

        with tempfile.TemporaryDirectory() as tmp:
            executable = Path(tmp, "engine")
            executable.write_text(
                "#!/bin/sh\nif [ \"$1\" = --version ]; then echo 1.2; else echo '{}'; fi\n"
            )
            executable.chmod(0o700)
            with patch("appsec_cli.external.engine", return_value=str(executable)):
                self.assertEqual(ExternalTool("engine", "1.1").json([]), {})
                with self.assertRaises(ToolError) as exc:
                    ExternalTool("engine", "1.3").json([])
                self.assertEqual(exc.exception.code, "binary_version_unsupported")
        with self.assertRaises(ToolError):
            ExternalTool("nonexistent-appsec-unit-check").json([])

    def test_project_cannot_enable_plugins_or_set_endpoint(self):
        with (
            tempfile.TemporaryDirectory() as tmp,
            patch.dict(os.environ, {"XDG_CONFIG_HOME": tmp}),
        ):
            path = Path(tmp, "project.toml")
            for text in [
                '[plugins]\nadditional=["extra"]',
                '[llm]\nendpoint="http://localhost"',
            ]:
                path.write_text(text)
                with self.assertRaises(ToolError) as exc:
                    settings(path)
                self.assertEqual(exc.exception.code, "config_forbidden_key")
            path.unlink()
            os.mkfifo(path)
            with self.assertRaises(ToolError):
                settings(path)

    def test_project_file_only_tightens(self):
        cwd = os.getcwd()
        self.addCleanup(os.chdir, cwd)
        with tempfile.TemporaryDirectory() as tmp:
            os.chdir(tmp)
            user = Path(tmp, "appsec-cli/config.toml")
            user.parent.mkdir()
            local = Path(tmp, ".appsec-cli.toml")

            def threshold(user_text, local_text, tool_default=None):
                user.write_text(user_text)
                local.write_text(local_text)
                with patch.dict(os.environ, {"XDG_CONFIG_HOME": tmp}):
                    return settings().threshold_for("score", tool_default)

            self.assertEqual(
                threshold('fail_on = "high"', 'fail_on = "never"'), ("high", True)
            )
            self.assertEqual(
                threshold('fail_on = "high"', 'fail_on = "medium"'), ("medium", False)
            )
            self.assertEqual(threshold("", 'fail_on = "never"'), ("low", True))
            self.assertEqual(
                threshold("", '[tools.score]\nfail_on = "high"', "never"),
                ("high", False),
            )
            self.assertEqual(
                threshold('[tools.score]\nfail_on = "medium"', 'fail_on = "critical"'),
                ("medium", True),
            )
            self.assertEqual(threshold('fail_on = "high"', ""), ("high", False))
            trusted = Path(tmp, "trusted.toml")
            trusted.write_text('fail_on = "never"')
            with patch.dict(os.environ, {"XDG_CONFIG_HOME": tmp}):
                self.assertEqual(
                    settings(trusted).threshold_for("score", None), ("never", False)
                )
            local.write_text('[tools."*"]\nfail_on = "never"')
            with (
                patch.dict(os.environ, {"XDG_CONFIG_HOME": tmp}),
                self.assertRaises(ToolError),
            ):
                settings()

    def test_score_status(self):
        gap = {"area": "coverage", "status": "unclear"}
        nested = {"area": "coverage", "status": "satisfied", "locations": [gap]}
        for rc, checks, status, diagnostic, exit_code in [
            (0, [], "ok", None, 1),
            (
                2,
                [{"area": "identity", "status": "unclear"}],
                "ok",
                "limited_evidence",
                1,
            ),
            (2, [gap], "partial", "limited_coverage", 3),
            (2, [nested], "partial", "limited_coverage", 3),
            (1, [], "partial", "limited_coverage", 3),
        ]:
            engine = {
                "analysis": "security-assessment",
                "overall": {"rating": "Bad"},
                "subscores": [{"score": 40}],
                "checks": checks,
                "findings": [
                    {
                        "rule": "PY-SQL",
                        "severity": "high",
                        "path": "a.py",
                        "line": 3,
                        "next_action": "Bind parameters.",
                    }
                ],
            }
            with (
                self.subTest(rc=rc, checks=checks),
                patch.object(security_score, "engine", return_value="engine"),
                patch.object(
                    security_score,
                    "invoke",
                    return_value=(rc, json.dumps(engine).encode()),
                ),
            ):
                result = security_score.score.handler(SimpleNamespace(args=["."]))
                _, code = finalize(
                    result,
                    "security-score",
                    security_score.score,
                    {},
                    "high",
                    "info",
                    None,
                )
                self.assertEqual(result.status, status)
                self.assertEqual(
                    [d.code for d in result.diagnostics or []],
                    [diagnostic] if diagnostic else [],
                )
                self.assertEqual(code, exit_code)
                finding = result.findings[0]
                self.assertEqual(finding.locations[0]["start_line"], 3)
                self.assertEqual(finding.remediation, "Bind parameters.")

    def test_report_projection(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, "verification.yaml")
            good = """meta: {schema_version: 1, generated: "2026-01-01", verifier_version: x, source_assessment: a, target: {}, scope: {file: null}, authorization: {confirmed: true, mode: ci-flag}, limits: {}}
results: [{result_id: VF-001, eligibility: {status: dynamic}, finding_ref: {id: F-1, match_key: a.py}, verdict: confirmed, unused_internal_field: private}]
"""
            path.write_text(good)
            data = export.handler(path).data
            self.assertEqual(data["annotations"][0]["verdict"], "confirmed")
            self.assertNotIn("private", json.dumps(data))
            for invalid in [
                good.replace("version: 1", "version: 2"),
                "x: &a test\ny: *a",
                "!!python/object:Test {}",
                "results: [{}]",
            ]:
                path.write_text(invalid)
                with self.assertRaises(ToolError):
                    export.handler(path)


ARCHITECTURE = {"assets": [], "data_flows": [], "trust_boundaries": []}


class Threats(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        initialize()

    def test_profiles(self):
        from appsec_analyzer.codex_schema import CodexSchema

        schema = commands.Review.model_json_schema()
        CodexSchema(schema)
        content = {"architecture": ARCHITECTURE, "threats": [], "open_questions": []}
        context = {"documents": []}
        for profile, key, reply in [
            (
                "anthropic-api",
                "ANTHROPIC_API_KEY",
                {
                    "stop_reason": "end_turn",
                    "content": [{"type": "text", "text": json.dumps(content)}],
                },
            ),
            (
                "litellm",
                "LITELLM_API_KEY",
                {
                    "choices": [
                        {
                            "finish_reason": "stop",
                            "message": {"content": json.dumps(content)},
                        }
                    ]
                },
            ),
        ]:
            with (
                patch.dict(os.environ, {}, clear=True),
                self.assertRaisesRegex(ToolError, key),
            ):
                hosts.complete(profile, "alias", context, schema, Path("."))
            with (
                patch.dict(
                    os.environ,
                    {
                        key: "unit-test",
                        "LITELLM_BASE_URL": "https://gateway.example/v1",
                    },
                    clear=True,
                ),
                patch.object(hosts, "post", return_value=reply) as post,
            ):
                self.assertEqual(
                    hosts.complete(profile, "alias", context, schema, Path(".")),
                    content,
                )
                url, _, body = post.call_args.args
                self.assertIn("https://", url)
                self.assertEqual(body["model"], "alias")
                post.return_value = {}
                with self.assertRaises(ToolError):
                    hosts.complete(profile, "alias", context, schema, Path("."))
        for profile, target in [
            ("claude", "runtime.analyst_host.ClaudeCliTransport"),
            ("codex-cli", "appsec_analyzer.codex_cli.CodexCliTransport"),
        ]:
            with (
                patch(target) as transport,
                patch("shutil.which", return_value="/usr/bin/test"),
                patch("appsec_analyzer.codex_cli.preflight", return_value={}),
            ):
                transport.return_value.invoke.return_value = SimpleNamespace(
                    payload=content
                )
                self.assertEqual(
                    hosts.complete(profile, "alias", context, schema, Path(".")),
                    content,
                )
                self.assertEqual(
                    transport.return_value.invoke.call_args.args[2], schema
                )
        with self.assertRaises(ToolError):
            hosts.post("http://example.org", {}, {})

    def test_gateway_errors(self):
        with patch.object(hosts.http.client, "HTTPSConnection") as connection:
            conn = connection.return_value
            for status, diagnostic in [
                (302, "host_failed"),
                (400, "model_request_rejected"),
                (401, "authentication_failed"),
            ]:
                conn.getresponse.return_value.status = status
                with self.assertRaises(ToolError) as exc:
                    hosts.post("https://gateway.example/v1/chat/completions", {}, {})
                self.assertEqual(exc.exception.code, diagnostic)
            self.assertEqual(connection.call_count, 3)
            conn.getresponse.side_effect = TimeoutError()
            with self.assertRaises(ToolError) as exc:
                hosts.post("https://gateway.example/v1/chat/completions", {}, {})
            self.assertEqual(exc.exception.code, "llm_timeout")

    def test_scopes_and_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)

            def git(*args):
                return (
                    subprocess.check_output(
                        [
                            "git",
                            "-C",
                            tmp,
                            "-c",
                            "user.name=test",
                            "-c",
                            "user.email=test@example.invalid",
                            *args,
                        ]
                    )
                    .decode()
                    .strip()
                )

            git("init", "-q")
            (repo / "controls.md").write_text("Existing authorization controls.")
            (repo / "app.py").write_text("version = 1\n")
            git("add", ".")
            git("commit", "-qm", "initial")
            base = git("rev-parse", "HEAD")
            (repo / "app.py").write_text("version = 2\n")
            git("commit", "-qam", "update")
            head = git("rev-parse", "HEAD")
            (repo / "app.py").write_text("uncommitted")
            empty = {"architecture": ARCHITECTURE, "threats": [], "open_questions": []}
            progress = io.StringIO()
            with (
                patch.object(hosts, "complete", return_value=empty) as transport,
                redirect_stderr(progress),
            ):
                result = commands.analyze.handler(repo)
                self.assertEqual(result.data["revision"], head)
                self.assertEqual(result.data["profile"], "claude")
                result = commands.analyze.handler(repo, commit="HEAD")
                self.assertEqual(result.data["base"], base)
                # before and after of app.py are one file
                self.assertEqual(
                    progress.getvalue().splitlines()[-1],
                    "Sending 2 files to claude (sonnet) for review. "
                    "This can take up to 3 minutes.",
                )
                docs = transport.call_args.args[2]["documents"]
                self.assertEqual(
                    {(r["side"], r["path"]) for r in docs},
                    {
                        ("context", "controls.md"),
                        ("before", "app.py"),
                        ("after", "app.py"),
                    },
                )
                self.assertNotIn("uncommitted", str(docs))
                from appsec_analyzer import review_sources

                with (
                    patch.object(
                        review_sources,
                        "resolve",
                        return_value={"head": head, "base": base},
                    ),
                    patch.object(
                        review_sources, "checkout", return_value=nullcontext(repo)
                    ),
                ):
                    result = commands.analyze.handler(
                        pr="https://github.com/team/project/pull/1"
                    )
                    self.assertEqual(result.target["kind"], "pull_request")
                    self.assertIn(
                        "Fetching https://github.com/team/project/pull/1",
                        progress.getvalue(),
                    )
                entry = {
                    "actor": "reader",
                    "prerequisites": "access",
                    "change": "existing",
                    "severity": "low",
                    "title": "control review",
                    "side": "context",
                    "path": "controls.md",
                    "line": 1,
                    "impact": "records exposed",
                    "existing_controls": "access check",
                    "remediation": "review authorization",
                }
                transport.return_value = {
                    **empty,
                    "threats": [
                        entry,
                        {**entry, "severity": "high"},
                        {**entry, "change": "mitigated"},
                    ],
                }
                reviewed = commands.analyze.handler(repo)
                self.assertEqual(
                    [f.severity for f in reviewed.findings], ["high", "low"]
                )
                self.assertEqual(len(reviewed.data["threats"]), 3)
                transport.return_value = empty
                (repo / "large.txt").write_text("x" * 40000)
                (repo / "external-link").symlink_to("/outside")
                git("add", ".")
                git("commit", "-qm", "coverage limits")
                coverage = commands.analyze.handler(repo)
                self.assertEqual(coverage.status, "partial")
                self.assertEqual(coverage.data["omission_reasons"]["file_too_large"], 1)
                self.assertEqual(coverage.data["omitted"], 2)
                transport.return_value = {
                    "architecture": ARCHITECTURE,
                    "threats": [],
                    "open_questions": ["Who can deploy?"],
                }
                self.assertEqual(commands.analyze.handler(repo).status, "partial")
                transport.return_value = {
                    "architecture": ARCHITECTURE,
                    "threats": [
                        {
                            "actor": "user",
                            "prerequisites": "access",
                            "change": "introduced",
                            "severity": "high",
                            "path": "made-up",
                            "side": "context",
                            "line": 1,
                            "impact": "test",
                            "title": "test",
                            "existing_controls": "unknown",
                            "remediation": "test",
                        }
                    ],
                    "open_questions": [],
                }
                with self.assertRaisesRegex(ToolError, "citation"):
                    commands.analyze.handler(repo)
