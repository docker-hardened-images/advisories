#!/usr/bin/env python3
"""Reject missing, malformed, or unrecognized scanner output."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


def fail(message: str) -> None:
    print(f"error: {message}", file=sys.stderr)
    raise SystemExit(1)


def load_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text())
    except Exception as exc:  # noqa: BLE001 - retain adapter output context.
        fail(f"{path} is not valid JSON: {exc}")
    if not isinstance(value, dict):
        fail(f"{path} must contain a JSON object")
    return value


def collect_purls(value: Any) -> set[str]:
    if isinstance(value, str):
        return {value} if value.startswith("pkg:") else set()
    if isinstance(value, list):
        result: set[str] = set()
        for item in value:
            result.update(collect_purls(item))
        return result
    if isinstance(value, dict):
        result = set()
        for item in value.values():
            result.update(collect_purls(item))
        return result
    return set()


def package_purls(doc: dict[str, Any]) -> set[str]:
    result: set[str] = set()
    for key in ("artifacts", "packages", "components"):
        value = doc.get(key)
        if isinstance(value, list):
            result.update(collect_purls(value))
    return result


def purl_identity(purl: str) -> str:
    return purl.split("?", 1)[0]


def validate_sbom(path: Path, expected_purls: list[str], expected_prefix: str) -> None:
    doc = load_object(path)
    if not any(isinstance(doc.get(key), list) for key in ("artifacts", "packages", "components")):
        fail(f"{path} is not a recognized Syft, SPDX, or CycloneDX SBOM object")

    purls = package_purls(doc)
    if not purls:
        fail(f"{path} contains no package PURLs")
    for expected_purl in expected_purls:
        expected_identity = purl_identity(expected_purl)
        if not any(purl_identity(purl) == expected_identity for purl in purls):
            fail(f"{path} does not contain expected package identity {expected_identity}")
    if not any(purl.startswith(expected_prefix) for purl in purls):
        fail(f"{path} does not contain expected package prefix {expected_prefix}")


def validate_scan(path: Path) -> None:
    doc = load_object(path)
    if isinstance(doc.get("matches"), list):
        findings = doc["matches"]
    elif isinstance(doc.get("runs"), list):
        if not doc["runs"]:
            fail(f"{path} SARIF runs must contain at least one scan run")
        findings = []
        for index, run in enumerate(doc["runs"]):
            if not isinstance(run, dict) or not isinstance(run.get("results", []), list):
                fail(f"{path} SARIF runs[{index}].results must be an array")
            findings.extend(run.get("results", []))
    else:
        fail(f"{path} is not recognized Grype JSON or SARIF")

    if not all(isinstance(finding, dict) for finding in findings):
        fail(f"{path} findings must be JSON objects")


def validate_membership(
    base_path: Path,
    derived_path: Path,
    expected_inherited_purls: list[str],
    expected_added_purls: list[str],
) -> None:
    base = {purl_identity(purl) for purl in package_purls(load_object(base_path))}
    derived = {purl_identity(purl) for purl in package_purls(load_object(derived_path))}
    inherited = base & derived
    added = derived - base
    removed = base - derived
    expected_inherited = {purl_identity(purl) for purl in expected_inherited_purls}
    expected_added = {purl_identity(purl) for purl in expected_added_purls}

    missing_inherited = expected_inherited - inherited
    if missing_inherited:
        fail(f"{derived_path} is missing inherited package identities {sorted(missing_inherited)}")
    if added != expected_added:
        fail(
            f"{derived_path} added package identities {sorted(added)}, "
            f"expected exactly {sorted(expected_added)}"
        )
    if removed:
        fail(f"{derived_path} removed base package identities {sorted(removed)}")


def main() -> None:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="kind", required=True)

    sbom_parser = subparsers.add_parser("sbom")
    sbom_parser.add_argument("path", type=Path)
    sbom_parser.add_argument("--expected-purl", action="append", default=[])
    sbom_parser.add_argument("--expected-prefix", required=True)

    scan_parser = subparsers.add_parser("scan")
    scan_parser.add_argument("path", type=Path)

    membership_parser = subparsers.add_parser("membership")
    membership_parser.add_argument("base_path", type=Path)
    membership_parser.add_argument("derived_path", type=Path)
    membership_parser.add_argument("--expected-inherited-purl", action="append", default=[])
    membership_parser.add_argument("--expected-added-purl", action="append", default=[])

    args = parser.parse_args()
    if args.kind == "sbom":
        validate_sbom(args.path, args.expected_purl, args.expected_prefix)
    elif args.kind == "scan":
        validate_scan(args.path)
    else:
        validate_membership(
            args.base_path,
            args.derived_path,
            args.expected_inherited_purl,
            args.expected_added_purl,
        )


if __name__ == "__main__":
    main()
