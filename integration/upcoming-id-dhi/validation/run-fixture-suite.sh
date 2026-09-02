#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../../.." && pwd)"
SCENARIOS_FILE="$SCRIPT_DIR/fixtures/scenarios.json"
ADAPTER=""
RUN_SCANNER=0
KEEP_IMAGES=0
PLATFORM=""

usage() {
  cat <<'EOF'
Usage: integration/upcoming-id-dhi/validation/run-fixture-suite.sh [options]

Options:
  --adapter PATH   Load a scanner adapter.
  --run-scanner    Run scanner-backed checks. Requires --adapter.
  --platform VALUE  Require scanner snapshots for this platform.
  --keep-images    Keep fixture images built in scanner-backed mode.
  --help           Show this help.

The default mode validates static fixtures only.
EOF
}

die() {
  echo "error: $*" >&2
  exit 1
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

require_function() {
  declare -f "$1" >/dev/null 2>&1 || die "adapter function not found: $1"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --adapter)
      [[ $# -ge 2 ]] || die "--adapter requires a value"
      ADAPTER="$2"
      shift 2
      ;;
    --run-scanner)
      RUN_SCANNER=1
      shift
      ;;
    --platform)
      [[ $# -ge 2 ]] || die "--platform requires a value"
      PLATFORM="$2"
      shift 2
      ;;
    --keep-images)
      KEEP_IMAGES=1
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      die "unknown argument: $1"
      ;;
  esac
done

require_cmd python3

python3 - "$ROOT_DIR" "$SCENARIOS_FILE" <<'PY'
from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from urllib.parse import parse_qs

root = Path(sys.argv[1])
scenarios_file = Path(sys.argv[2])
base = scenarios_file.parent
errors: list[str] = []

DHI_VERSIONED = re.compile(r"^pkg:(apk|deb)/dhi/[^@?]+@[^?]+(?:\?.*)?$")
DHI_PREFIX = re.compile(r"^pkg:(apk|deb)/dhi/[^@?]+@$")
DHI_PURL = re.compile(
    r"^pkg:(?P<type>apk|deb)/dhi/(?P<name>[^@?]+)"
    r"(?P<version>@[^?]+)?(?:\?(?P<query>.*))?$"
)
UPSTREAM_NS = re.compile(r"^pkg:(apk/alpine|deb/debian)/")
VALID_STATUS = {"not_affected", "affected", "fixed", "under_investigation"}
RANGE_EVENT_KEYS = {"introduced", "fixed", "last_affected", "limit"}
PACKAGE_ROUTINGS = {
    "dhi-os-package",
    "non-dhi-owned-os-package",
}
FIXTURE_KINDS = {"scanner-snapshot", "static-contract"}
PINNED_IMAGE = re.compile(r"^.+@sha256:[0-9a-f]{64}$")
PLATFORM = re.compile(r"^linux/(amd64|arm64)$")
SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
LINEAGE_BY_PURL_TYPE = {"apk": "alpine", "deb": "debian"}
ECOSYSTEM_LINEAGE_BY_PURL_TYPE = {"apk": "Alpine", "deb": "Debian"}


def fail(where: str, message: str) -> None:
    errors.append(f"{where}: {message}")


def load_json(path: Path) -> object:
    try:
        return json.loads(path.read_text())
    except Exception as exc:  # noqa: BLE001 - validation should report path context.
        fail(str(path.relative_to(root)), f"cannot read JSON: {exc}")
        return {}


def parse_dhi_purl(
    where: str,
    purl: object,
    *,
    require_version: bool,
    field: str,
) -> dict[str, object] | None:
    if not isinstance(purl, str):
        fail(where, f"{field} must be a string")
        return None

    match = DHI_PURL.match(purl)
    if match is None:
        fail(where, f"{field} must match pkg:(apk|deb)/dhi/<name>[...]: {purl}")
        return None

    version = match.group("version")
    if require_version and version is None:
        fail(where, f"{field} must include an explicit package version: {purl}")
    if not require_version and version is not None:
        fail(where, f"{field} must not include a package version: {purl}")

    query = match.group("query")
    parsed_qualifiers = {
        key: values[0]
        for key, values in parse_qs(query or "", keep_blank_values=True).items()
        if values
    }

    for qualifier in ("os_distro", "os_name", "os_version"):
        if not parsed_qualifiers.get(qualifier):
            fail(where, f"{field} must include {qualifier}: {purl}")

    if parsed_qualifiers.get("os_name") != "dhi":
        fail(where, f"{field} must use os_name=dhi: {purl}")

    purl_type = match.group("type")
    expected_distro = LINEAGE_BY_PURL_TYPE[purl_type]
    if parsed_qualifiers.get("os_distro") != expected_distro:
        fail(
            where,
            f"{field} type {purl_type} must use os_distro={expected_distro}: {purl}",
        )

    return {
        "type": purl_type,
        "name": match.group("name"),
        "version": version[1:] if version else None,
        "qualifiers": parsed_qualifiers,
    }


def expected_ecosystem(parsed: dict[str, object]) -> str:
    qualifiers = parsed["qualifiers"]
    assert isinstance(qualifiers, dict)
    return (
        "Docker Hardened Images:"
        f"{ECOSYSTEM_LINEAGE_BY_PURL_TYPE[str(parsed['type'])]}:"
        f"{qualifiers.get('os_version', '')}"
    )


def parse_scanner_dhi_purl(where: str, purl: str) -> dict[str, str] | None:
    match = DHI_PURL.match(purl)
    if match is None or match.group("version") is None:
        fail(where, f"scanner-observed PURL must be a versioned DHI PURL: {purl}")
        return None

    qualifiers = parse_qs(match.group("query") or "", keep_blank_values=True)
    distro_values = qualifiers.get("distro", [])
    if len(distro_values) != 1 or not distro_values[0].startswith("dhi-"):
        fail(where, f"scanner-observed PURL must include distro=dhi-<release>: {purl}")
        return None

    release = distro_values[0][len("dhi-"):]
    if not release:
        fail(where, f"scanner-observed PURL distro release must not be empty: {purl}")
        return None

    purl_type = match.group("type")
    return {
        "type": purl_type,
        "name": match.group("name"),
        "version": match.group("version")[1:],
        "release": release,
        "ecosystem": (
            "Docker Hardened Images:"
            f"{ECOSYSTEM_LINEAGE_BY_PURL_TYPE[purl_type]}:{release}"
        ),
    }


def package_key(parsed: dict[str, object], *, include_version: bool) -> tuple[str, ...]:
    parsed_qualifiers = parsed["qualifiers"]
    assert isinstance(parsed_qualifiers, dict)
    key = (
        str(parsed["type"]),
        str(parsed["name"]),
        str(parsed_qualifiers.get("os_distro", "")),
        str(parsed_qualifiers.get("os_name", "")),
        str(parsed_qualifiers.get("os_version", "")),
    )
    if include_version:
        return (*key, str(parsed["version"]))
    return key


def version_tokens(version: str) -> list[tuple[int, int | str]]:
    tokens: list[tuple[int, int | str]] = []
    for token in re.findall(r"\d+|[A-Za-z]+", version):
        if token.isdigit():
            tokens.append((0, int(token)))
        else:
            tokens.append((1, token))
    return tokens


# Fixture-scoped comparison for these synthetic ranges. Scanner integrations
# still need package-manager-native version ordering for production results.
def compare_versions(left: str, right: str) -> int:
    if left == right:
        return 0

    left_tokens = version_tokens(left)
    right_tokens = version_tokens(right)
    for left_token, right_token in zip(left_tokens, right_tokens):
        if left_token == right_token:
            continue
        return -1 if left_token < right_token else 1

    if len(left_tokens) == len(right_tokens):
        return 0
    return -1 if len(left_tokens) < len(right_tokens) else 1


def version_in_events(version: str, events: object) -> bool:
    if not isinstance(events, list):
        return False

    affected = False
    for event in events:
        if not isinstance(event, dict) or len(event) != 1:
            continue
        key, value = next(iter(event.items()))
        value = str(value)
        if key == "introduced":
            affected = compare_versions(version, value) >= 0
        elif key in {"fixed", "limit"}:
            if compare_versions(version, value) >= 0:
                affected = False
        elif key == "last_affected":
            if compare_versions(version, value) > 0:
                affected = False
    return affected


def entry_ranges_match_version(entry: dict[str, object], version: str) -> bool:
    ranges = entry.get("ranges", [])
    if not isinstance(ranges, list):
        return False
    for version_range in ranges:
        if (
            isinstance(version_range, dict)
            and version_range.get("type") == "ECOSYSTEM"
            and version_in_events(version, version_range.get("events"))
        ):
            return True
    return False


def entry_matches_version(entry: dict[str, object], version: str) -> bool:
    versions = entry.get("versions", [])
    return (
        isinstance(versions, list)
        and version in versions
    ) or entry_ranges_match_version(entry, version)


def osv_component_purls(osv: dict[str, object]) -> set[str]:
    purls = set()
    affected = osv.get("affected", [])
    if not isinstance(affected, list):
        return purls
    for entry in affected:
        if not isinstance(entry, dict):
            continue
        database_specific = entry.get("database_specific", {})
        if not isinstance(database_specific, dict):
            continue
        component_packages = database_specific.get("component_packages", [])
        if not isinstance(component_packages, list):
            continue
        for component in component_packages:
            if isinstance(component, dict) and isinstance(component.get("purl"), str):
                purls.add(component["purl"])
    return purls


def sbom_has_component_parent(sbom: dict[str, object], component_purl: str, parent_purl: str) -> bool:
    packages = sbom.get("packages", [])
    if not isinstance(packages, list):
        return False
    return any(
        isinstance(package, dict)
        and package.get("purl") == component_purl
        and package.get("origin") == "embedded-language-component"
        and package.get("parent_purl") == parent_purl
        for package in packages
    )


def validate_scanner_snapshot_sbom(
    where: str,
    sbom: dict[str, object],
    source_images: list[str],
) -> None:
    if sbom.get("schema") != "dhi-osv-vex-transition.example-sbom/v1":
        fail(where, "scanner snapshot sbom.json must use the example SBOM v1 schema")

    image = sbom.get("image")
    if not isinstance(image, str) or not image.startswith("local/"):
        fail(where, "scanner snapshot sbom.json image must identify the local simulated image")

    image_id = sbom.get("image_id")
    if not isinstance(image_id, str) or not SHA256.match(image_id):
        fail(where, "scanner snapshot sbom.json image_id must be a sha256 digest")

    if sbom.get("source_images") != source_images:
        fail(where, "scanner snapshot sbom.json source_images must exactly match the scenario snapshots")

    layers = sbom.get("layers")
    if not isinstance(layers, list) or not layers:
        fail(where, "scanner snapshot sbom.json layers must be a non-empty ordered array")
        return

    layer_ids: set[str] = set()
    for expected_index, layer in enumerate(layers):
        if not isinstance(layer, dict):
            fail(where, f"sbom.json layers[{expected_index}] must be an object")
            continue
        if layer.get("index") != expected_index:
            fail(where, f"sbom.json layers[{expected_index}].index must be {expected_index}")
        digest = layer.get("digest")
        if not isinstance(digest, str) or not SHA256.match(digest):
            fail(where, f"sbom.json layers[{expected_index}].digest must be a sha256 digest")
        elif digest in layer_ids:
            fail(where, f"sbom.json layer digest must be unique: {digest}")
        else:
            layer_ids.add(digest)
        role = layer.get("role")
        if not isinstance(role, str) or not role:
            fail(where, f"sbom.json layers[{expected_index}].role must be a non-empty string")

    packages = sbom.get("packages")
    if not isinstance(packages, list):
        return
    for package_index, package in enumerate(packages):
        if not isinstance(package, dict):
            continue
        package_name = str(package.get("name", package_index))
        catalog = package.get("catalog_evidence")
        if not isinstance(catalog, dict):
            fail(where, f"SBOM package {package_name} must include catalog_evidence")
        else:
            if not isinstance(catalog.get("path"), str) or not catalog.get("path"):
                fail(where, f"SBOM package {package_name} catalog_evidence.path must be non-empty")
            if catalog.get("layer_id") not in layer_ids:
                fail(where, f"SBOM package {package_name} catalog layer must resolve to sbom.json layers")

        file_evidence = package.get("file_evidence")
        if not isinstance(file_evidence, list) or not file_evidence:
            fail(where, f"SBOM package {package_name} must include file_evidence")
            continue
        for evidence_index, evidence in enumerate(file_evidence):
            if not isinstance(evidence, dict):
                fail(where, f"SBOM package {package_name} file_evidence[{evidence_index}] must be an object")
                continue
            if not isinstance(evidence.get("path"), str) or not evidence.get("path"):
                fail(where, f"SBOM package {package_name} file_evidence[{evidence_index}].path must be non-empty")
            if evidence.get("layer_id") not in layer_ids:
                fail(
                    where,
                    f"SBOM package {package_name} file evidence layer must resolve to sbom.json layers",
                )


doc = load_json(scenarios_file)
if not isinstance(doc, dict):
    fail(str(scenarios_file.relative_to(root)), "top-level value must be an object")
    scenarios = []
else:
    scenarios = doc.get("scenarios", [])
    if not isinstance(scenarios, list) or not scenarios:
        fail(str(scenarios_file.relative_to(root)), "scenarios must be a non-empty array")
        scenarios = []

for scenario in scenarios:
    if not isinstance(scenario, dict):
        fail(str(scenarios_file.relative_to(root)), "scenario entries must be objects")
        continue

    sid = str(scenario.get("id", "<missing-id>"))
    where = f"scenario {sid}"
    if scenario.get("model") != "id-dhi":
        fail(where, "model must be id-dhi")
    if scenario.get("family") not in {"alpine", "debian"}:
        fail(where, "family must be alpine or debian")
    scanner_backed = scenario.get("scanner_backed")
    if not isinstance(scanner_backed, bool):
        fail(where, "scanner_backed must be a boolean")
        scanner_backed = False
    expected_fixture_kind = "scanner-snapshot" if scanner_backed else "static-contract"
    if scenario.get("fixture_kind") not in FIXTURE_KINDS:
        fail(where, f"fixture_kind must be one of {sorted(FIXTURE_KINDS)}")
    if scenario.get("fixture_kind") != expected_fixture_kind:
        fail(where, f"fixture_kind must be {expected_fixture_kind} when scanner_backed={scanner_backed}")
    if scenario.get("image_snapshot") is not scanner_backed:
        fail(where, f"image_snapshot must be {str(scanner_backed).lower()} when scanner_backed={scanner_backed}")
    routing = str(scenario.get("package_routing", "dhi-os-package"))
    if routing not in PACKAGE_ROUTINGS:
        fail(where, f"package_routing must be one of {sorted(PACKAGE_ROUTINGS)}")
        routing = "dhi-os-package"
    expected_behavior = scenario.get("expected_behavior", {})
    if not isinstance(expected_behavior, dict):
        fail(where, "expected_behavior must be an object")
        expected_behavior = {}
    component_purl = expected_behavior.get("component_package_purl")
    if component_purl is not None and not isinstance(component_purl, str):
        fail(where, "expected_behavior.component_package_purl must be a string when set")
        component_purl = None

    example_dir = (base / str(scenario.get("example_dir", ""))).resolve()
    if not example_dir.is_dir():
        fail(where, f"example_dir does not exist: {example_dir}")
        continue

    source_images: list[str] = []
    if scanner_backed:
        platform = scenario.get("platform")
        if not isinstance(platform, str) or not PLATFORM.match(platform):
            fail(where, "scanner snapshots must declare platform as linux/amd64 or linux/arm64")
        for field in ("source_image", "upstream_source_image"):
            source_image = scenario.get(field)
            if field == "upstream_source_image" and source_image is None:
                continue
            if not isinstance(source_image, str) or not PINNED_IMAGE.match(source_image):
                fail(where, f"{field} must be an immutable sha256 image reference")
                continue
            source_images.append(source_image)
        dockerfile_path = example_dir / "Dockerfile"
        if not dockerfile_path.is_file():
            fail(where, "scanner snapshots must include a Dockerfile")
        else:
            dockerfile = dockerfile_path.read_text()
            for source_image in source_images:
                if source_image not in dockerfile:
                    fail(where, f"Dockerfile must use declared snapshot image {source_image}")
    elif "source_image" in scenario:
        fail(where, "static contract fixtures must use source_reference, not source_image")

    observed = str(scenario.get("scanner_observed_package_purl", ""))
    observed_prefix = str(scenario.get("scanner_observed_package_purl_prefix", ""))
    observed_purls_value = scenario.get("scanner_observed_package_purls")
    if observed_purls_value is None:
        observed_purls = [observed] if observed else []
    elif not isinstance(observed_purls_value, list) or not all(
        isinstance(purl, str) and DHI_VERSIONED.match(purl)
        for purl in observed_purls_value
    ):
        fail(where, "scanner_observed_package_purls must contain versioned DHI package PURLs")
        observed_purls = []
    else:
        observed_purls = observed_purls_value
    if observed and observed not in observed_purls:
        fail(where, "scanner_observed_package_purls must include scanner_observed_package_purl")
    observed_parsed = {
        purl: parsed
        for purl in observed_purls
        if (parsed := parse_scanner_dhi_purl(where, purl)) is not None
    }
    canonical = str(scenario.get("canonical_package_purl", ""))
    upstream = str(scenario.get("upstream_like_package_purl", ""))
    canonical_parsed = None
    if routing == "dhi-os-package":
        if not DHI_VERSIONED.match(observed):
            fail(where, "scanner_observed_package_purl must be versioned pkg:(apk|deb)/dhi")
        canonical_parsed = parse_dhi_purl(
            where,
            canonical,
            require_version=True,
            field="canonical_package_purl",
        )
        if upstream and not UPSTREAM_NS.match(upstream):
            fail(where, "upstream_like_package_purl must use upstream apk/deb namespace")

        if canonical_parsed is not None:
            canonical_q = canonical_parsed["qualifiers"]
            assert isinstance(canonical_q, dict)
            if canonical_q.get("os_distro") != scenario.get("family"):
                fail(where, "canonical_package_purl os_distro must match scenario family")
            primary_observed = observed_parsed.get(observed)
            if primary_observed is not None:
                canonical_identity = (
                    canonical_parsed["type"],
                    canonical_parsed["name"],
                    canonical_parsed["version"],
                    canonical_q.get("os_version"),
                )
                observed_identity = (
                    primary_observed["type"],
                    primary_observed["name"],
                    primary_observed["version"],
                    primary_observed["release"],
                )
                if observed_identity != canonical_identity:
                    fail(
                        where,
                        "scanner-observed and canonical package PURLs must map to "
                        "the same type, name, version, and release",
                    )
                if primary_observed["ecosystem"] != expected_ecosystem(canonical_parsed):
                    fail(
                        where,
                        "scanner-observed and canonical package PURLs must derive "
                        "the same release-scoped ecosystem",
                    )
    else:
        if observed:
            if not DHI_VERSIONED.match(observed):
                fail(where, "non-dhi-owned-os-package observed PURL must be versioned pkg:(apk|deb)/dhi")
        elif not DHI_PREFIX.match(observed_prefix):
            fail(where, "non-dhi-owned-os-package must set a DHI observed PURL or PURL prefix")
        if expected_behavior.get("dhi_osv_used") is not False:
            fail(where, "non-dhi-owned-os-package must set expected_behavior.dhi_osv_used=false")
        if expected_behavior.get("requires_dhi_product_membership") is not True:
            fail(where, "non-dhi-owned-os-package must require DHI product membership")
        if expected_behavior.get("scanner_observed_dhi_namespace") is not True:
            fail(where, "non-dhi-owned-os-package must record scanner_observed_dhi_namespace=true")

    sbom = load_json(example_dir / "sbom.json")
    if isinstance(sbom, dict):
        if scanner_backed:
            if sbom.get("platform") != scenario.get("platform"):
                fail(where, "sbom.json platform must match the scanner snapshot")
            sbom_sources = {str(sbom.get("image", ""))}
            declared_sbom_sources = sbom.get("source_images", [])
            if isinstance(declared_sbom_sources, list):
                sbom_sources.update(str(item) for item in declared_sbom_sources)
            for source_image in source_images:
                if source_image not in sbom_sources:
                    fail(where, f"sbom.json must record snapshot image {source_image}")
            validate_scanner_snapshot_sbom(where, sbom, source_images)
        packages = sbom.get("packages", [])
        if not isinstance(packages, list) or not packages:
            fail(where, "sbom.json packages must be non-empty")
        dhi_packages = [
            package for package in packages
            if isinstance(package, dict)
            and str(package.get("purl", "")).startswith("pkg:")
            and "/dhi/" in str(package.get("purl", ""))
        ]
        if routing == "dhi-os-package" and not dhi_packages:
            fail(where, "sbom.json must include at least one DHI package PURL")
        target_packages = [
            package for package in packages
            if isinstance(package, dict)
            and (
                package.get("purl") == observed
                or package.get("canonical_purl") == canonical
                or (
                    observed_prefix
                    and str(package.get("purl", "")).startswith(observed_prefix)
                )
                or package.get("purl_prefix") == observed_prefix
            )
        ]
        if not target_packages:
            fail(where, "sbom.json must include the scenario target package PURL")
        sbom_package_purls = {
            str(package.get("purl"))
            for package in packages
            if isinstance(package, dict) and isinstance(package.get("purl"), str)
        }
        missing_observed_purls = set(observed_purls) - sbom_package_purls
        if missing_observed_purls:
            fail(
                where,
                "sbom.json is missing scanner-observed package PURLs: "
                f"{sorted(missing_observed_purls)}",
            )
        for package in packages:
            if (
                routing == "dhi-os-package"
                and isinstance(package, dict)
                and UPSTREAM_NS.match(str(package.get("purl", "")))
            ):
                fail(where, "sbom.json DHI fixture package must not use upstream namespace")
        if routing == "non-dhi-owned-os-package":
            if not any(
                isinstance(package, dict)
                and package.get("origin") == "customer-layer"
                and (
                    DHI_VERSIONED.match(str(package.get("purl", "")))
                    or package.get("purl_prefix") == observed_prefix
                )
                for package in packages
            ):
                fail(where, "non-dhi-owned-os-package must include a customer-layer DHI-namespace package")
        if (
            isinstance(component_purl, str)
            and routing == "dhi-os-package"
            and not sbom_has_component_parent(sbom, component_purl, canonical)
        ):
            fail(
                where,
                "expected component_package_purl must appear in sbom.json as an "
                "embedded-language-component with parent_purl=canonical_package_purl",
            )

    osv_ref = scenario.get("osv")
    vex_ref = scenario.get("vex")
    osv_path = example_dir / str(osv_ref) if osv_ref else None
    vex_path = example_dir / str(vex_ref) if vex_ref else None
    expected_path = example_dir / str(scenario.get("expected", ""))
    osv = load_json(osv_path) if osv_path is not None else None
    vex = load_json(vex_path) if vex_path is not None else None
    expected = load_json(expected_path)

    base_membership = scenario.get("base_membership")
    if base_membership is not None:
        if not isinstance(base_membership, dict):
            fail(where, "base_membership must be an object")
        elif not isinstance(sbom, dict):
            fail(where, "base_membership requires a valid derived sbom.json")
        else:
            base_example_ref = base_membership.get("example_dir")
            if not isinstance(base_example_ref, str) or not base_example_ref:
                fail(where, "base_membership.example_dir must be a relative path")
            elif not (example_dir / base_example_ref).resolve().is_dir():
                fail(where, "base_membership.example_dir must resolve to a fixture directory")
            base_sbom_ref = base_membership.get("sbom")
            if not isinstance(base_sbom_ref, str) or not base_sbom_ref:
                fail(where, "base_membership.sbom must be a relative path")
                base_sbom = {}
            else:
                base_sbom = load_json((example_dir / base_sbom_ref).resolve())

            def package_purls(document: object) -> set[str]:
                if not isinstance(document, dict):
                    return set()
                document_packages = document.get("packages", [])
                if not isinstance(document_packages, list):
                    return set()
                return {
                    str(package.get("purl"))
                    for package in document_packages
                    if isinstance(package, dict) and isinstance(package.get("purl"), str)
                }

            base_purls = package_purls(base_sbom)
            derived_purls = package_purls(sbom)
            inherited_purls = base_purls & derived_purls
            added_purls = derived_purls - base_purls

            base_layers = base_sbom.get("layers", []) if isinstance(base_sbom, dict) else []
            derived_layers = sbom.get("layers", [])
            if not isinstance(base_layers, list) or not base_layers:
                fail(where, "base membership SBOM must declare an ordered layer list")
                base_layers = []
            if not isinstance(derived_layers, list) or not derived_layers:
                fail(where, "derived membership SBOM must declare an ordered layer list")
                derived_layers = []
            base_layer_ids_ordered = [
                layer.get("digest")
                for layer in base_layers
                if isinstance(layer, dict)
            ]
            derived_layer_ids_ordered = [
                layer.get("digest")
                for layer in derived_layers
                if isinstance(layer, dict)
            ]
            if len(derived_layer_ids_ordered) <= len(base_layer_ids_ordered):
                fail(where, "derived membership SBOM must add at least one layer after the base")
            elif base_layer_ids_ordered != derived_layer_ids_ordered[:len(base_layer_ids_ordered)]:
                fail(where, "base SBOM layer digests must be an exact prefix of the derived SBOM layers")

            base_layer_ids = {
                str(layer.get("digest"))
                for layer in base_layers
                if isinstance(layer, dict) and isinstance(layer.get("digest"), str)
            }
            final_derived_layer = (
                derived_layers[-1].get("digest")
                if derived_layers and isinstance(derived_layers[-1], dict)
                else None
            )
            declared_inherited = base_membership.get("inherited_package_purls")
            declared_added = base_membership.get("added_package_purls")
            if (
                not isinstance(declared_inherited, list)
                or not all(isinstance(purl, str) for purl in declared_inherited)
                or set(declared_inherited) != inherited_purls
            ):
                fail(
                    where,
                    "base_membership.inherited_package_purls must equal the base/derived SBOM intersection",
                )
            if (
                not isinstance(declared_added, list)
                or not all(isinstance(purl, str) for purl in declared_added)
                or set(declared_added) != added_purls
            ):
                fail(
                    where,
                    "base_membership.added_package_purls must equal the derived-minus-base SBOM difference",
                )

            derived_packages = {
                str(package.get("purl")): package
                for package in sbom.get("packages", [])
                if isinstance(package, dict) and isinstance(package.get("purl"), str)
            }
            for purl in inherited_purls:
                package = derived_packages[purl]
                if package.get("membership_evidence") != "present-in-dhi-base-sbom":
                    fail(where, f"inherited package {purl} must record DHI base-SBOM membership")
                file_layers = {
                    str(evidence.get("layer_id"))
                    for evidence in package.get("file_evidence", [])
                    if isinstance(evidence, dict) and isinstance(evidence.get("layer_id"), str)
                }
                if not file_layers & base_layer_ids:
                    fail(where, f"inherited package {purl} must retain file evidence in a base layer")
            for purl in added_purls:
                package = derived_packages[purl]
                if package.get("membership_evidence") != "absent-from-dhi-base-sbom":
                    fail(where, f"added package {purl} must record absence from the DHI base SBOM")
                file_layers = {
                    str(evidence.get("layer_id"))
                    for evidence in package.get("file_evidence", [])
                    if isinstance(evidence, dict) and isinstance(evidence.get("layer_id"), str)
                }
                if not file_layers - base_layer_ids:
                    fail(where, f"added package {purl} must include file evidence outside the base layers")

            for purl, package in derived_packages.items():
                catalog = package.get("catalog_evidence", {})
                if not isinstance(catalog, dict) or catalog.get("layer_id") != final_derived_layer:
                    fail(where, f"derived package {purl} catalog evidence must point at the final catalog layer")

            if isinstance(expected, dict):
                if expected.get("base_membership") != base_membership:
                    fail(where, "expected.json base_membership must match the scenario")
                package_routes = expected.get("package_routes")
                if not isinstance(package_routes, list):
                    fail(where, "expected.json package_routes must be an array")
                    package_routes = []
                routes_by_purl = {
                    str(route.get("purl")): route
                    for route in package_routes
                    if isinstance(route, dict) and isinstance(route.get("purl"), str)
                }
                if set(routes_by_purl) != derived_purls:
                    fail(where, "expected.json package_routes must cover every derived SBOM package")
                for purl in inherited_purls:
                    route = routes_by_purl.get(purl, {})
                    if route.get("membership_evidence") != "present-in-dhi-base-sbom":
                        fail(where, f"inherited package route {purl} must use base-SBOM evidence")
                    if route.get("dhi_osv_used") is not True:
                        fail(where, f"inherited package route {purl} must apply DHI OSV")
                    for field in ("osv", "vex"):
                        route_ref = route.get(field)
                        if not isinstance(route_ref, str) or not (example_dir / route_ref).resolve().is_file():
                            fail(where, f"inherited package route {purl} must reference a {field.upper()} fixture")
                for purl in added_purls:
                    route = routes_by_purl.get(purl, {})
                    if route.get("membership_evidence") != "absent-from-dhi-base-sbom":
                        fail(where, f"added package route {purl} must record absent base membership")
                    if route.get("dhi_osv_used") is not False:
                        fail(where, f"added package route {purl} must not apply DHI OSV")
                    if route.get("osv") is not None or route.get("vex") is not None:
                        fail(where, f"added package route {purl} must not reference DHI OSV/VEX")

    derived_expected_finding = None
    osv_advisory_id = None
    osv_upstream: set[str] = set()
    matching_affected_entries: list[dict[str, object]] = []

    if expected_behavior.get("expected_finding") is True and osv is None:
        fail(where, "expected_finding=true requires an OSV fixture")

    if isinstance(osv, dict):
        advisory_id = osv.get("id")
        if not isinstance(advisory_id, str) or not advisory_id.startswith("DHI-"):
            fail(where, "OSV id must use DHI- prefix")
        else:
            osv_advisory_id = advisory_id
        upstream_refs = osv.get("upstream", [])
        if isinstance(upstream_refs, list):
            osv_upstream = {ref for ref in upstream_refs if isinstance(ref, str)}
        affected = osv.get("affected", [])
        if not isinstance(affected, list) or not affected:
            fail(where, "OSV affected must be non-empty")
        for index, entry in enumerate(affected):
            if not isinstance(entry, dict):
                fail(where, f"OSV affected[{index}] must be an object")
                continue
            package = entry.get("package", {})
            if not isinstance(package, dict):
                fail(where, f"OSV affected[{index}].package must be an object")
                continue
            parsed_purl = parse_dhi_purl(
                where,
                package.get("purl"),
                require_version=False,
                field=f"OSV affected[{index}].package.purl",
            )
            if parsed_purl is not None:
                required_ecosystem = expected_ecosystem(parsed_purl)
                if package.get("ecosystem") != required_ecosystem:
                    fail(
                        where,
                        f"OSV affected[{index}].package.ecosystem must be {required_ecosystem}",
                    )
                if package.get("name") != parsed_purl["name"]:
                    fail(where, f"OSV affected[{index}].package.name must match package.purl")
                if (
                    routing == "dhi-os-package"
                    and canonical_parsed is not None
                    and package_key(parsed_purl, include_version=False)
                    == package_key(canonical_parsed, include_version=False)
                ):
                    matching_affected_entries.append(entry)

            versions = entry.get("versions", [])
            if not isinstance(versions, list):
                fail(where, f"OSV affected[{index}].versions must be an array")
                versions = []
            elif not all(isinstance(version, str) and version for version in versions):
                fail(where, f"OSV affected[{index}].versions must contain non-empty strings")
            elif len(versions) != len(set(versions)):
                fail(where, f"OSV affected[{index}].versions must not contain duplicates")

            ranges = entry.get("ranges", [])
            if not isinstance(ranges, list):
                fail(where, f"OSV affected[{index}].ranges must be an array")
                ranges = []
            if not versions and not ranges:
                fail(
                    where,
                    f"OSV affected[{index}] must contain exact versions, ranges, or both",
                )
            for range_index, version_range in enumerate(ranges):
                if not isinstance(version_range, dict):
                    fail(where, f"OSV affected[{index}].ranges[{range_index}] must be an object")
                    continue
                if version_range.get("type") != "ECOSYSTEM":
                    fail(where, f"OSV affected[{index}].ranges[{range_index}].type must be ECOSYSTEM")
                events = version_range.get("events")
                if not isinstance(events, list) or not events:
                    fail(where, f"OSV affected[{index}].ranges[{range_index}].events must not be empty")
                    continue
                if not any(isinstance(event, dict) and "introduced" in event for event in events):
                    fail(where, f"OSV affected[{index}].ranges[{range_index}] must include introduced")
                for event_index, event in enumerate(events):
                    if not isinstance(event, dict) or len(event) != 1:
                        fail(
                            where,
                            f"OSV affected[{index}].ranges[{range_index}]"
                            f".events[{event_index}] must have one event key",
                        )
                        continue
                    key = next(iter(event))
                    if key not in RANGE_EVENT_KEYS:
                        fail(
                            where,
                            f"OSV affected[{index}].ranges[{range_index}]"
                            f".events[{event_index}] has unsupported key {key!r}",
                        )
        if isinstance(component_purl, str) and component_purl:
            if component_purl not in osv_component_purls(osv):
                fail(
                    where,
                    "expected component_package_purl must appear in OSV "
                    "affected[].database_specific.component_packages",
                )

        if routing == "dhi-os-package" and canonical_parsed is not None:
            installed_version = str(canonical_parsed["version"])
            if not matching_affected_entries:
                fail(where, "OSV affected packages must include the scenario canonical_package_purl identity")
                derived_expected_finding = False
            else:
                derived_expected_finding = any(
                    entry_matches_version(entry, installed_version)
                    for entry in matching_affected_entries
                )

            expected_status = expected_behavior.get("vex_status")
            if expected_status == "under_investigation":
                ui_versions: set[str] = set()
                for entry in matching_affected_entries:
                    versions = entry.get("versions", [])
                    ranges = entry.get("ranges", [])
                    if not isinstance(versions, list) or not versions:
                        fail(where, "under_investigation OSV coverage must enumerate exact versions")
                    else:
                        ui_versions.update(str(version) for version in versions)
                    if isinstance(ranges, list) and ranges:
                        fail(where, "under_investigation OSV coverage must omit affected ranges")
                if ui_versions != {installed_version}:
                    fail(
                        where,
                        "under_investigation OSV versions must equal the exact version "
                        f"covered by the fixture assessment ({installed_version})",
                    )
            elif expected_status in {"affected", "fixed"}:
                for entry in matching_affected_entries:
                    versions = entry.get("versions", [])
                    ranges = entry.get("ranges", [])
                    if not isinstance(versions, list) or not versions:
                        fail(where, f"{expected_status} OSV fixture must enumerate resolved versions")
                    if not isinstance(ranges, list) or not ranges:
                        fail(where, f"{expected_status} OSV fixture must retain its native range")
                    if isinstance(versions, list):
                        for version in versions:
                            if isinstance(version, str) and not entry_ranges_match_version(entry, version):
                                fail(
                                    where,
                                    f"{expected_status} resolved version {version} must fall "
                                    "within the fixture's native range",
                                )

            non_matching_versions = expected_behavior.get("non_matching_versions", [])
            if expected_status == "under_investigation" and not non_matching_versions:
                fail(
                    where,
                    "under_investigation expected_behavior.non_matching_versions "
                    "must include at least one unlisted negative test version",
                )
            if not isinstance(non_matching_versions, list) or not all(
                isinstance(version, str) and version for version in non_matching_versions
            ):
                fail(where, "expected_behavior.non_matching_versions must contain strings")
            else:
                for non_matching_version in non_matching_versions:
                    if any(
                        entry_matches_version(entry, non_matching_version)
                        for entry in matching_affected_entries
                    ):
                        fail(
                            where,
                            "expected non-matching version is covered by OSV: "
                            f"{non_matching_version}",
                        )
    elif routing == "dhi-os-package":
        derived_expected_finding = False

    declared_expected_finding = expected_behavior.get("expected_finding")
    if routing == "dhi-os-package":
        if not isinstance(declared_expected_finding, bool):
            fail(where, "dhi-os-package scenarios must set expected_behavior.expected_finding")
        elif (
            derived_expected_finding is not None
            and derived_expected_finding != declared_expected_finding
        ):
            fail(
                where,
                "expected_behavior.expected_finding must match the OSV versions/ranges result "
                f"for canonical_package_purl ({derived_expected_finding})",
            )

    if isinstance(vex, dict):
        statements = vex.get("statements", [])
        if not isinstance(statements, list) or not statements:
            fail(where, "VEX statements must be non-empty")
        matching_vex_statuses = []
        matching_vex_component = False
        for index, statement in enumerate(statements):
            if not isinstance(statement, dict):
                fail(where, f"VEX statements[{index}] must be an object")
                continue
            if statement.get("status") not in VALID_STATUS:
                fail(where, f"VEX statements[{index}].status is not supported")
            vulnerability = statement.get("vulnerability", {})
            if not isinstance(vulnerability, dict):
                fail(where, f"VEX statements[{index}].vulnerability must be an object")
                vulnerability = {}
            vulnerability_name = vulnerability.get("name")
            if vex_path is not None and vulnerability_name != vex_path.stem:
                fail(where, f"VEX statements[{index}].vulnerability.name must match filename stem")
            if osv_advisory_id is not None and vulnerability_name != osv_advisory_id:
                fail(where, f"VEX statements[{index}].vulnerability.name must match OSV id")
            aliases = vulnerability.get("aliases", [])
            if aliases is not None:
                if not isinstance(aliases, list) or not all(isinstance(alias, str) for alias in aliases):
                    fail(where, f"VEX statements[{index}].vulnerability.aliases must be strings")
                elif osv_upstream:
                    unknown_aliases = set(aliases).difference(osv_upstream)
                    if unknown_aliases:
                        fail(
                            where,
                            "VEX statements"
                            f"[{index}].vulnerability.aliases are not in OSV upstream: "
                            f"{sorted(unknown_aliases)}",
                        )

            products = statement.get("products", [])
            if not isinstance(products, list) or not products:
                fail(where, f"VEX statements[{index}].products must be non-empty")
                continue
            statement_matches_scenario = False
            for pindex, product in enumerate(products):
                if not isinstance(product, dict):
                    fail(where, f"VEX statements[{index}].products[{pindex}] must be an object")
                    continue
                parsed_product = parse_dhi_purl(
                    where,
                    product.get("@id"),
                    require_version=True,
                    field=f"VEX statements[{index}].products[{pindex}].@id",
                )
                if (
                    parsed_product is not None
                    and canonical_parsed is not None
                    and package_key(parsed_product, include_version=True)
                    == package_key(canonical_parsed, include_version=True)
                ):
                    statement_matches_scenario = True
                    subcomponents = product.get("subcomponents", [])
                    if (
                        isinstance(component_purl, str)
                        and isinstance(subcomponents, list)
                        and any(
                            isinstance(subcomponent, dict)
                            and subcomponent.get("@id") == component_purl
                            for subcomponent in subcomponents
                        )
                    ):
                        matching_vex_component = True
            if statement_matches_scenario:
                matching_vex_statuses.append(statement.get("status"))

        if routing == "dhi-os-package" and canonical_parsed is not None:
            if not matching_vex_statuses:
                fail(where, "VEX products must include the scenario canonical_package_purl identity")
            expected_status = expected_behavior.get("vex_status")
            if isinstance(expected_status, str) and expected_status:
                if expected_status not in matching_vex_statuses:
                    fail(where, f"VEX statement for scenario package must include expected status {expected_status}")
            if isinstance(component_purl, str) and not matching_vex_component:
                fail(
                    where,
                    "expected component_package_purl must appear in VEX "
                    "subcomponents for the scenario package",
                )

    if isinstance(expected, dict):
        if expected.get("model") != "id-dhi":
            fail(where, "expected.json model must be id-dhi")
        if expected.get("fixture_kind") != expected_fixture_kind:
            fail(where, f"expected.json fixture_kind must be {expected_fixture_kind}")
        if expected.get("image_snapshot") is not scanner_backed:
            fail(where, f"expected.json image_snapshot must be {str(scanner_backed).lower()}")
        if scanner_backed:
            if expected.get("platform") != scenario.get("platform"):
                fail(where, "expected.json platform must match the scanner snapshot")
            for field in ("source_image", "upstream_source_image"):
                if field in scenario and expected.get(field) != scenario.get(field):
                    fail(where, f"expected.json {field} must match the scenario")
        elif "source_reference" in scenario:
            if expected.get("source_reference") != scenario.get("source_reference"):
                fail(where, "expected.json source_reference must match the scenario")
        if expected.get("package_routing", routing) != routing:
            fail(where, "expected.json package_routing must match scenario")
        if expected.get("expected_finding") != expected_behavior.get("expected_finding"):
            fail(where, "expected.json expected_finding must match expected_behavior")
        if routing == "dhi-os-package":
            if expected.get("upstream_lookup_for_dhi_layer") is not False:
                fail(where, "expected.json must set upstream_lookup_for_dhi_layer=false")
            if expected.get("dhi_layer_os_packages_use_dhi_namespace") is not True:
                fail(where, "expected.json must set dhi_layer_os_packages_use_dhi_namespace=true")
        else:
            if expected.get("dhi_osv_used") is not False:
                fail(where, "expected.json must set dhi_osv_used=false")
            if expected.get("scanner_observed_dhi_namespace") is not True:
                fail(where, "expected.json must set scanner_observed_dhi_namespace=true")
            if expected.get("requires_dhi_product_membership") is not True:
                fail(where, "expected.json must set requires_dhi_product_membership=true")

if errors:
    print("Upcoming ID=dhi fixture validation failed:", file=sys.stderr)
    for error in errors:
        print(f" - {error}", file=sys.stderr)
    sys.exit(1)

print(f"OK: validated {len(scenarios)} upcoming ID=dhi fixture scenario(s)")
PY

if [[ "$RUN_SCANNER" -eq 1 ]]; then
  [[ -n "$ADAPTER" ]] || die "--run-scanner requires --adapter"
fi

if [[ -n "$ADAPTER" ]]; then
  [[ -f "$ADAPTER" ]] || die "adapter not found: $ADAPTER"
  # shellcheck disable=SC1090
  source "$ADAPTER"
  require_function scanner_name
  require_function scanner_preflight
  require_function scanner_sbom_json
  require_function scanner_scan_json
  require_function scanner_scan_with_vex_json
  scanner_preflight

  name="$(scanner_name)"
  echo "OK: adapter preflight passed for $name"
  if declare -f scanner_version >/dev/null 2>&1; then
    echo "Scanner version:"
    scanner_version | sed 's/^/  /'
  fi
  if declare -f scanner_database_status >/dev/null 2>&1; then
    echo "Scanner database:"
    scanner_database_status | sed 's/^/  /'
  fi

  if [[ "$RUN_SCANNER" -eq 1 ]]; then
    echo "Scanner observation time: $(date -u +'%Y-%m-%dT%H:%M:%SZ')"
    require_cmd docker
    work_dir="$(mktemp -d "${TMPDIR:-/tmp}/dhi-id-dhi-validation.XXXXXX")"
    built_images=()
    cleanup() {
      if [[ "$KEEP_IMAGES" -eq 0 && "${#built_images[@]}" -gt 0 ]]; then
        docker image rm -f "${built_images[@]}" >/dev/null 2>&1 || true
      fi
      rm -rf "$work_dir"
    }
    trap cleanup EXIT

    scanner_scenarios_file="$work_dir/scenarios.tsv"
    python3 - "$SCENARIOS_FILE" > "$scanner_scenarios_file" <<'PY'
from __future__ import annotations

import json
import sys
from pathlib import Path

scenarios_file = Path(sys.argv[1])
base = scenarios_file.parent
doc = json.loads(scenarios_file.read_text())
for scenario in doc["scenarios"]:
    if not scenario.get("scanner_backed", True):
        continue
    example_dir = (base / scenario["example_dir"]).resolve()
    vex_ref = scenario.get("vex")
    vex_path = example_dir / vex_ref if vex_ref else "-"
    observed_purls = scenario.get("scanner_observed_package_purls")
    if observed_purls is None:
        observed_purl = scenario.get("scanner_observed_package_purl")
        observed_purls = [observed_purl] if observed_purl else []
    observed_prefix = scenario.get("scanner_observed_package_purl_prefix")
    base_membership = scenario.get("base_membership", {})
    base_example_ref = base_membership.get("example_dir")
    base_example_dir = (example_dir / base_example_ref).resolve() if base_example_ref else "-"
    inherited_purls = base_membership.get("inherited_package_purls", [])
    added_purls = base_membership.get("added_package_purls", [])
    print("\t".join([
        scenario["id"],
        scenario["family"],
        scenario["platform"],
        str(example_dir),
        str(vex_path),
        "|".join(observed_purls) or "-",
        observed_prefix or "-",
        str(base_example_dir),
        "|".join(inherited_purls) or "-",
        "|".join(added_purls) or "-",
    ]))
PY

    expected_scanner_scenarios="$(wc -l < "$scanner_scenarios_file")"
    [[ "$expected_scanner_scenarios" -gt 0 ]] || die "scenario manifest selected zero scanner-backed fixtures"
    executed_scanner_scenarios=0

    while IFS=$'\t' read -r scenario_id family scenario_platform example_dir vex_path expected_purls expected_purl_prefix base_example_dir inherited_purls added_purls; do
      if [[ -n "$PLATFORM" && "$PLATFORM" != "$scenario_platform" ]]; then
        die "fixture $scenario_id is pinned to $scenario_platform, not requested platform $PLATFORM"
      fi
      tag="dhi-id-dhi-${scenario_id}-$$"
      build_args=(-t "$tag" --platform "$scenario_platform")
      build_args+=("$example_dir")

      echo "Building scanner fixture $scenario_id"
      docker build "${build_args[@]}" >/dev/null
      built_images+=("$tag")

      sbom_output="$work_dir/$scenario_id.sbom.json"
      scan_output="$work_dir/$scenario_id.scan.json"
      vex_scan_output="$work_dir/$scenario_id.scan-with-vex.json"

      scanner_sbom_json "$tag" "$sbom_output" || die "$name failed to produce an SBOM for $scenario_id"
      expected_prefix="pkg:apk/dhi/"
      if [[ "$family" == "debian" ]]; then
        expected_prefix="pkg:deb/dhi/"
      fi
      if [[ "$expected_purl_prefix" != "-" ]]; then
        expected_prefix="$expected_purl_prefix"
      fi
      sbom_validation=(sbom "$sbom_output" --expected-prefix "$expected_prefix")
      if [[ "$expected_purls" != "-" ]]; then
        IFS='|' read -r -a expected_purl_values <<< "$expected_purls"
        for expected_purl in "${expected_purl_values[@]}"; do
          sbom_validation+=(--expected-purl "$expected_purl")
        done
      fi
      python3 "$SCRIPT_DIR/validate-scanner-output.py" "${sbom_validation[@]}"

      if [[ "$base_example_dir" != "-" ]]; then
        base_tag="${tag}-base"
        echo "Building base membership fixture for $scenario_id"
        docker build -t "$base_tag" --platform "$scenario_platform" "$base_example_dir" >/dev/null
        built_images+=("$base_tag")

        base_sbom_output="$work_dir/$scenario_id.base.sbom.json"
        scanner_sbom_json "$base_tag" "$base_sbom_output" || \
          die "$name failed to produce the base SBOM for $scenario_id"
        membership_validation=(membership "$base_sbom_output" "$sbom_output")
        if [[ "$inherited_purls" != "-" ]]; then
          IFS='|' read -r -a inherited_purl_values <<< "$inherited_purls"
          for inherited_purl in "${inherited_purl_values[@]}"; do
            membership_validation+=(--expected-inherited-purl "$inherited_purl")
          done
        fi
        if [[ "$added_purls" != "-" ]]; then
          IFS='|' read -r -a added_purl_values <<< "$added_purls"
          for added_purl in "${added_purl_values[@]}"; do
            membership_validation+=(--expected-added-purl "$added_purl")
          done
        fi
        python3 "$SCRIPT_DIR/validate-scanner-output.py" "${membership_validation[@]}"
        echo "OK: base-SBOM membership validated for $scenario_id"
      fi

      scanner_scan_json "$tag" "$scan_output" || die "$name failed to scan $scenario_id"
      python3 "$SCRIPT_DIR/validate-scanner-output.py" scan "$scan_output"
      if [[ "$vex_path" != "-" ]]; then
        scanner_scan_with_vex_json "$tag" "$vex_path" "$vex_scan_output" || \
          die "$name failed to scan $scenario_id with VEX"
        python3 "$SCRIPT_DIR/validate-scanner-output.py" scan "$vex_scan_output"
      fi
      executed_scanner_scenarios=$((executed_scanner_scenarios + 1))
      echo "OK: scanner-backed fixture output validated for $scenario_id"
    done < "$scanner_scenarios_file"

    if [[ "$executed_scanner_scenarios" -ne "$expected_scanner_scenarios" ]]; then
      die "executed $executed_scanner_scenarios of $expected_scanner_scenarios scanner-backed fixtures"
    fi
    echo "OK: validated $executed_scanner_scenarios scanner-backed fixture output(s)"
  fi
fi
