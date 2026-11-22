"""Check pinned wheel digests, yanks and known advisories using the PyPI release API."""

import json
import re
from pathlib import Path
from urllib.request import urlopen


def main():
    root = Path(__file__).resolve().parents[1]
    rows = [
        row
        for lock in ("requirements-linux-py310.lock", "requirements-dev.lock")
        for row in (root / lock).read_text().splitlines()
    ]
    for row in rows:
        if not row or row.startswith("#"):
            continue
        name, version, digest = re.fullmatch(
            r"([\w-]+)==([\w.]+) --hash=sha256:([0-9a-f]{64})", row
        ).groups()
        with urlopen(
            f"https://pypi.org/pypi/{name}/{version}/json", timeout=20
        ) as response:
            record = json.load(response)
        usable = any(
            item["digests"]["sha256"] == digest
            and not item["yanked"]
            and item["packagetype"] == "bdist_wheel"
            for item in record["urls"]
        )
        advisories = [
            v["id"] for v in record["vulnerabilities"] if not v.get("withdrawn")
        ]
        if not usable or advisories:
            raise SystemExit(
                f"Review {name} {version}: digest accepted={usable}, advisories={advisories}"
            )
        print(name, version, "OK")


if __name__ == "__main__":
    main()
