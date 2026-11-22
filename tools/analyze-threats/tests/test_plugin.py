"""analyze-threats adapter: model profiles, review scopes and cited evidence.

Run with the Python of an installed suite:
python -m unittest discover -s tools/analyze-threats/tests
"""

import io
import json
import os
import subprocess
import tempfile
import unittest
from contextlib import nullcontext, redirect_stderr
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from appsec_cli import ToolError
from appsec_plugin_analyze_threats import commands, hosts
from appsec_analyzer.engine import initialize


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


if __name__ == "__main__":
    unittest.main()
