"""security-score adapter: what it passes to the engine and how it maps the result.

Run with the Python of an installed suite:
python -m unittest discover -s tools/security-score/tests
"""

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import click
from appsec_cli import ToolError
from appsec_cli.external import engine, invoke
from appsec_cli.output import finalize
from appsec_plugin_security_score import commands as security_score

commands = security_score
score = commands.score


def run(*args):
    """The adapter's handler with the arguments that follow the tool name."""
    return score.handler(SimpleNamespace(args=list(args)))


def engine_returns(report, rc=0):
    """Patches that replace the engine with one that prints report."""
    return (
        patch.object(commands, "engine", return_value="engine"),
        patch.object(
            commands, "invoke", return_value=(rc, json.dumps(report).encode())
        ),
    )


class Score(unittest.TestCase):
    def test_engine_errors_reach_the_user(self):
        with self.assertRaises(ToolError) as exc:
            run("/nonexistent/appsec")
        self.assertEqual(exc.exception.code, "score_failed")
        self.assertIn("does not exist", str(exc.exception))
        with self.assertRaises(click.UsageError) as usage:
            run("--repo", ".", ".")
        self.assertIn(
            "security-score: Choose a positional repository or --repo",
            usage.exception.format_message(),
        )

    def test_scores_a_repository_and_a_change(self):
        with tempfile.TemporaryDirectory() as tmp:

            def git(*args):
                subprocess.run(
                    [
                        "git",
                        "-C",
                        tmp,
                        "-c",
                        "user.name=Test",
                        "-c",
                        "user.email=test@example.invalid",
                        *args,
                    ],
                    check=True,
                    capture_output=True,
                )

            git("init", "-q")
            Path(tmp, "README.md").write_text("Initial\n")
            git("add", ".")
            git("commit", "-qm", "initial")
            Path(tmp, "notes.md").write_text("Release notes\n")
            git("add", ".")
            git("commit", "-qm", "doc update")
            result = run(tmp)
            self.assertEqual(result.status, "ok", result)
            self.assertIn("rating", result.data)
            change = run(tmp, "--commit", "HEAD")
            self.assertIn("relevance", change.data)

    def test_help_is_the_engine_help(self):
        self.assertEqual(score.engine_help, ("security-score", "--help"))
        code, out = invoke([engine(score.engine_help[0]), *score.engine_help[1:]])
        self.assertEqual(code, 0)
        self.assertIn(b"usage: security-score", out)
        self.assertIn(b"--repo REPO", out)
        self.assertIn("GIT_TOKEN", score.handler.__doc__)

    def test_passes_its_arguments_to_the_engine(self):
        url = "https://github.com/OWNER/REPO"
        report = {
            "analysis": "security-assessment",
            "overall": {"rating": "Good"},
            "subscores": [{"score": 80}],
            "checks": [],
            "findings": [],
        }
        for args in [
            (url,),
            ("--repo", url),
            (".", "--checks", "JS-SQL", "--timeout", "30"),
            ("--skip-checks", "PY-SQL"),
            ("--commit", "HEAD", "--details"),
            ("--checks", "X", "--", "--update"),  # after --, an argument
        ]:
            first, second = engine_returns(report)
            with self.subTest(args=args), first, second as call:
                self.assertEqual(run(*args).status, "ok")
                self.assertEqual(call.call_args.args[0], ["engine", "--json", *args])

    def test_target_comes_from_the_engine(self):
        url = "https://github.com/OWNER/REPO"
        for scope, target in [
            (
                {
                    "kind": "repository",
                    "selection": "git-url",
                    "repository": url,
                    "revision": "0123abcd",
                },
                {"kind": "repository", "url": url, "revision": "0123abcd"},
            ),
            (
                {
                    "kind": "change",
                    "selection": "git",
                    "repository": "/src/app",
                    "base": "aaa1",
                    "head": "bbb2",
                },
                {
                    "kind": "change",
                    "path": "/src/app",
                    "base": "aaa1",
                    "head": "bbb2",
                    "revision": "bbb2",
                },
            ),
        ]:
            report = {
                "analysis": "change-relevance",
                "relevance": "low",
                "checks": [],
                "scope": scope,
            }
            first, second = engine_returns(report)
            with self.subTest(scope=scope), first, second:
                self.assertEqual(run(url).target, target)

    def test_git_token_reaches_only_github_and_gitlab(self):
        report = {"analysis": "change-relevance", "relevance": "low", "checks": []}
        cases = [
            (("https://github.com/OWNER/REPO",), True),
            (("https://gitlab.com/GROUP/PROJECT",), True),
            (("--repo=https://github.com/OWNER/REPO",), True),
            ((".",), True),
            (("https://gitlab.example.com/GROUP/PROJECT",), False),
            (("https://github.com.example.com/OWNER/REPO",), False),
            (("https://github.com@example.com/OWNER/REPO",), False),
            (("https://github.com:8443/OWNER/REPO",), False),
            (("http://github.com/OWNER/REPO",), False),
            (
                (
                    ".",
                    "--pr",
                    "https://gitlab.example.com/GROUP/PROJECT/-/merge_requests/1",
                ),
                False,
            ),
        ]
        for args, forwarded in cases:
            first, second = engine_returns(report)
            with (
                self.subTest(args=args),
                patch.dict(os.environ, {"GIT_TOKEN": "test-token", "NO_COLOR": "1"}),
                first,
                second as call,
            ):
                run(*args)
                # In the terminal the engine runs with the same environment.
                terminal = score.passthrough(SimpleNamespace(args=list(args)))
                self.assertEqual(terminal.argv, ["engine", *args])
                for env in (call.call_args.kwargs["env"], terminal.env):
                    if forwarded:
                        self.assertIsNone(env)  # inherits GIT_TOKEN
                    else:
                        self.assertNotIn("GIT_TOKEN", env)
                        self.assertEqual(env["NO_COLOR"], "1")

    def test_unreadable_remote_repository(self):
        def stop(message):
            def engine_run(argv, **kwargs):
                kwargs["stderr"].extend(message)
                return 1, b""

            return engine_run

        for message, expected in [
            (b"", "a private repository needs GIT_TOKEN"),
            (b"Reading sources...\nRepository not found.\n", "Repository not found."),
        ]:
            with (
                self.subTest(message=message),
                patch.object(commands, "engine", return_value="engine"),
                patch.object(commands, "invoke", side_effect=stop(message)),
                self.assertRaises(ToolError) as exc,
            ):
                run("https://github.com/OWNER/REPO")
            self.assertEqual(exc.exception.code, "repository_unavailable")
            self.assertIn(expected, str(exc.exception))

    def test_keeps_its_reserved_engine_options(self):
        # The CLI refuses these and their abbreviations before the engine starts;
        # the JSON options only with --format json or sarif, where it reads the JSON.
        for option in ("--update", "--analyzer", "--token-env"):
            with self.subTest(option=option):
                self.assertIn(option, score.forward_except)
        for option in ("--yaml", "--quiet", "--legacy-score", "--list-checks"):
            with self.subTest(option=option):
                self.assertIn(option, score.json_except)
                self.assertNotIn(option, score.forward_except)

    def test_engine_usage_error_is_a_usage_error(self):
        def refuse(argv, **kwargs):
            kwargs["stderr"].extend(
                b"usage: security-score [-h]\n"
                b"security-score: error: unrecognized arguments: --bogus\n"
            )
            return 2, b""

        with (
            patch.object(commands, "engine", return_value="engine"),
            patch.object(commands, "invoke", side_effect=refuse),
            self.assertRaises(click.UsageError) as exc,
        ):
            run(".", "--bogus")
        self.assertEqual(
            exc.exception.format_message(),
            "security-score: unrecognized arguments: --bogus",
        )

    def test_details(self):
        report = {
            "analysis": "security-assessment",
            "overall": {"rating": "Bad"},
            "subscores": [
                {
                    "title": "Identity & access",
                    "score": 59,
                    "rating": "Bad",
                    "reason": "Fast password hash",
                    "breakdown": [
                        {
                            "rule": "JS-SQL",
                            "severity": "high",
                            "title": "SQL text",
                            "file": "a.ts",
                        }
                    ],
                },
                {"title": "AI & agents", "score": None, "rating": "Not applicable"},
            ],
            "overview": {
                "languages": [{"language": "TypeScript", "files": 630}],
                "files": {"read": 1436, "lines": 287045},
                "frameworks": ["Express"],
                "routes": {"total": 110},
                "runtimes": [{"runtime": "Node.js", "version": "24"}],
                "development": {
                    "ci": [{"system": "GitHub Actions"}],
                    "security_tools": ["CodeQL"],
                },
            },
            "checks": [],
            "findings": [
                {
                    "rule": "JS-SQL",
                    "severity": "high",
                    "title": "SQL text",
                    "file": "a.ts",
                }
            ],
        }
        plain = {k: v for k, v in report.items() if k != "overview"}
        first, second = engine_returns(report)
        with first, second:
            result = run(".", "--details")
        self.assertEqual([f.severity for f in result.findings], ["high"])
        self.assertEqual(
            result.data["areas"][1],
            {
                "area": "AI & agents",
                "score": None,
                "rating": "Not applicable",
                "reason": None,
            },
        )
        self.assertEqual(result.data["overview"]["languages"], {"TypeScript": 630})
        first, second = engine_returns(plain)
        with first, second:
            data = run(".").data
        self.assertEqual((data["areas"], data["overview"]), (None, None))

    def test_findings_are_the_weaknesses_the_engine_scores(self):
        # The engine's findings list also holds what it only marks for review.
        # Its score and count use the area breakdowns; so do findings and gate.
        report = {
            "analysis": "security-assessment",
            "overall": {"rating": "Bad"},
            "checks": [],
            "findings": [
                {
                    "rule": "JS-SQL",
                    "severity": "high",
                    "title": "SQL text",
                    "file": "a.ts",
                    "line": 3,
                    "next_action": "Bind parameters.",
                },
                {
                    "rule": "JS-EVAL",
                    "severity": "high",
                    "title": "Code evaluation",
                    "file": "b.ts",
                    "line": 5,
                    "next_action": "Keep input as data.",
                },
                {
                    "rule": "JS-COOKIE",
                    "severity": "low",
                    "title": "Cookie flags",
                    "file": "c.ts",
                    "line": 7,
                },
            ],
            "subscores": [
                {
                    "score": 59,
                    "breakdown": [
                        # The design check owns the SQL finding at its location.
                        {
                            "rule": "DESIGN-DATA-BOUNDARY",
                            "rules": ["DESIGN-DATA-BOUNDARY", "JS-SQL"],
                            "severity": "high",
                            "title": "Request data in SQL text",
                            "file": "a.ts",
                            "line": 3,
                        }
                    ],
                }
            ],
            "review_hints": [
                {
                    "rule": "JS-EVAL",
                    "severity": "high",
                    "title": "Code evaluation",
                    "file": "b.ts",
                    "line": 5,
                    "reason": "Needs verification.",
                    "disposition": "review",
                },
                {
                    "rule": "JS-COOKIE",
                    "severity": "low",
                    "title": "Cookie flags",
                    "file": "c.ts",
                    "line": 7,
                    "reason": "Fixed cookie.",
                    "disposition": "neutral",
                },
            ],
        }
        first, second = engine_returns(report)
        with first, second:
            result = run(".")
        body, code = finalize(result, "security-score", score, {}, "high", "info", None)
        self.assertEqual(
            [f.rule for f in result.findings], ["security-score/DESIGN-DATA-BOUNDARY"]
        )
        self.assertEqual(result.findings[0].remediation, "Bind parameters.")
        self.assertEqual(body["counts"]["high"], 1)
        self.assertEqual(code, 1)
        self.assertEqual(
            body["data"]["review"],
            [
                {
                    "rule": "JS-EVAL",
                    "title": "Code evaluation",
                    "severity": "high",
                    "path": "b.ts",
                    "line": 5,
                    "reason": "Needs verification.",
                }
            ],
        )
        self.assertEqual(
            [(d.code, d.message) for d in result.diagnostics],
            [
                (
                    "manual_review",
                    "1 further observation needs manual review; see data.review.",
                )
            ],
        )

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
                "subscores": [
                    {
                        "score": 40,
                        "breakdown": [
                            {
                                "rule": "PY-SQL",
                                "severity": "high",
                                "title": "SQL text",
                                "file": "a.py",
                                "line": 3,
                            }
                        ],
                    }
                ],
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


if __name__ == "__main__":
    unittest.main()
