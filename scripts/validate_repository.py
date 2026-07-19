#!/usr/bin/env python3
"""Fail CI when portfolio evidence or security invariants regress."""

from __future__ import annotations

import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def tracked_files() -> list[Path]:
    result = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=ROOT,
        check=True,
        capture_output=True,
    )
    return [ROOT / item.decode() for item in result.stdout.split(b"\0") if item]


def main() -> int:
    failures: list[str] = []
    files = tracked_files()
    forbidden_suffixes = {".zip", ".pyc", ".pyo", ".tfstate", ".png", ".jpg", ".jpeg"}
    for path in files:
        if path.suffix.lower() in forbidden_suffixes:
            failures.append(f"tracked generated or unsanitized artifact: {path.relative_to(ROOT)}")

    patterns = {
        "historic AWS account ID": re.compile(rb"1349" rb"43601314"),
        "historic API endpoint ID": re.compile(rb"3v4d" rb"qt4pcb"),
        "AWS access key": re.compile(rb"(?:AKI" rb"A|ASI" rb"A)[A-Z0-9]{16}"),
        "OpenAI-style secret": re.compile(rb"sk-[A-Za-z0-9_-]{20,}"),
        "Slack token": re.compile(rb"xox[baprs]-[A-Za-z0-9-]{10,}"),
    }
    for path in files:
        try:
            content = path.read_bytes()
        except OSError as exc:
            failures.append(f"cannot read {path.relative_to(ROOT)}: {exc}")
            continue
        for label, pattern in patterns.items():
            if pattern.search(content):
                failures.append(f"{label} found in {path.relative_to(ROOT)}")

    receiver = (ROOT / "lambda_soar/slack_action_receiver.py").read_text()
    required_receiver_markers = (
        "CONTAINMENT_FAILED",
        "verify_slack_signature",
        "list_attached_role_policies",
        "ConditionExpression",
        "ALLOWED_TARGET_ROLES",
    )
    for marker in required_receiver_markers:
        if marker not in receiver:
            failures.append(f"receiver invariant missing: {marker}")
    if re.search(r"except\s+Exception\s*:\s*pass", receiver):
        failures.append("receiver silently discards an exception")

    readme = (ROOT / "README.md").read_text()
    for marker in ("647", "600-second", "Six starter", "AccessDenied"):
        if marker not in readme:
            failures.append(f"bounded evidence marker missing from README: {marker}")

    try:
        ET.parse(ROOT / "docs/images/aegis-soar-evidence.svg")
    except ET.ParseError as exc:
        failures.append(f"invalid evidence SVG: {exc}")

    if failures:
        print("Repository validation failed:")
        for failure in failures:
            print(f"- {failure}")
        return 1
    print(f"Validated {len(files)} tracked files and SOAR safety invariants.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
