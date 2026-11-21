"""Build a bounded, immutable review context from Git blobs, never the worktree."""

import os
import re
import shutil
import time
from collections import Counter
from pathlib import PurePosixPath

from appsec_cli import ToolError
from appsec_cli.external import invoke

MAX_CONTEXT = 160_000
MAX_FILES = 100
MAX_FILE = 32_768


def git(repo, *args):
    binary = shutil.which("git", path=os.defpath)
    if not binary:
        raise ToolError("git_missing", "Git is required to read repository revisions.")
    env = {
        "PATH": os.defpath,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_ALLOW_PROTOCOL": "",
        "LC_ALL": "C",
    }
    code, raw = invoke(
        [binary, "--no-pager", "-C", str(repo), *args],
        env=env,
        cap=8_000_000,
        timeout=15,
    )
    if code:
        raise ToolError(
            "source_unavailable", "Cannot read the selected Git repository or revision."
        )
    return raw


def revision(repo, value):
    if not re.fullmatch(r"HEAD|[a-fA-F0-9]{4,64}", value):
        raise ToolError("invalid_revision", "Use HEAD or a hexadecimal commit ID.")
    return (
        git(repo, "rev-parse", "--verify", "--end-of-options", value + "^{commit}")
        .decode()
        .strip()
    )


def tree(repo, rev):
    files = {}
    for item in git(repo, "ls-tree", "--full-tree", "-rlz", rev).split(b"\0"):
        if item:
            meta, path = item.split(b"\t", 1)
            mode, kind, oid, size = meta.split()
            files[path.decode("utf-8", "replace")] = (
                mode,
                oid.decode(),
                int(size) if kind == b"blob" else 0,
            )
    return files


def snapshot(repo, head, base=None, *, change=False):
    from contexts.build_analyst_snapshot import rejection_reason
    from runtime.model_secrets import ModelSecrets

    after = tree(repo, head)
    before = tree(repo, base) if base else {}
    changed = (
        sorted(p for p in after.keys() | before.keys() if before.get(p) != after.get(p))
        if change
        else []
    )
    selected = [
        (side, p, record)
        for p in changed
        for side, record in (("before", before.get(p)), ("after", after.get(p)))
        if record
    ]
    same = set(after) - set(changed)
    changed_dirs = {PurePosixPath(path).parent for path in changed}
    # Keep requirements and architecture close to the changes they explain.
    ordered = sorted(
        same,
        key=lambda p: (
            not any(
                w in p.lower()
                for w in ("readme", "architecture", "threat", "requirements")
            ),
            PurePosixPath(p).parent not in changed_dirs,
            p,
        ),
    )
    selected.extend(("context", p, after[p]) for p in ordered)
    documents = []
    gaps = Counter()
    total = reads = 0
    deadline = time.monotonic() + 60
    for side, path, (mode, oid, size) in selected:
        reason = rejection_reason(path, b"", {"file_kib": 32})
        if mode not in (b"100644", b"100755") or reason:
            gaps[reason or "special_file"] += 1
            continue
        if size > MAX_FILE:
            gaps["file_too_large"] += 1
            continue
        if (
            total + size > MAX_CONTEXT
            or len(documents) >= MAX_FILES
            or reads >= 300
            or time.monotonic() >= deadline
        ):
            gaps["context_limit"] += 1
            continue
        reads += 1
        raw = git(repo, "cat-file", "blob", oid)
        reason = rejection_reason(path, raw, {"file_kib": 32})
        if reason:
            gaps[reason] += 1
            continue
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            gaps["encoding"] += 1
            continue
        documents.append({"side": side, "path": path, "source": text})
        total += size
    if not documents:
        raise ToolError(
            "empty_context", "No eligible source documents in the selected revision."
        )
    cleaner = ModelSecrets.configured()
    documents = cleaner.protect(documents)
    return documents, dict(gaps), cleaner
