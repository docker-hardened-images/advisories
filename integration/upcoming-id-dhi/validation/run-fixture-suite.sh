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
  --platform VALUE  Pass --platform to docker build in scanner-backed mode.
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

    return {
        "type": match.group("type"),
        "name": match.group("name"),
        "version": version[1:] if version else None,
        "qualifiers": parsed_qualifiers,
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


def entry_matches_version(entry: dict[str, object], version: str) -> bool:
    ranges = entry.get("ranges")
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

    observed = str(scenario.get("scanner_observed_package_purl", ""))
    observed_prefix = str(scenario.get("scanner_observed_package_purl_prefix", ""))
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
            if package.get("ecosystem") != "Docker Hardened Images":
                fail(where, f"OSV affected[{index}].package.ecosystem must be Docker Hardened Images")
            if parsed_purl is not None:
                if package.get("name") != parsed_purl["name"]:
                    fail(where, f"OSV affected[{index}].package.name must match package.purl")
                if (
                    routing == "dhi-os-package"
                    and canonical_parsed is not None
                    and package_key(parsed_purl, include_version=False)
                    == package_key(canonical_parsed, include_version=False)
                ):
                    matching_affected_entries.append(entry)

            ranges = entry.get("ranges", [])
            if not isinstance(ranges, list) or not ranges:
                fail(where, f"OSV affected[{index}].ranges must contain at least one range")
                continue
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
            if not matching_affected_entries:
                fail(where, "OSV affected packages must include the scenario canonical_package_purl identity")
                derived_expected_finding = False
            else:
                installed_version = str(canonical_parsed["version"])
                derived_expected_finding = any(
                    entry_matches_version(entry, installed_version)
                    for entry in matching_affected_entries
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
                "expected_behavior.expected_finding must match the OSV range result "
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

  if [[ "$RUN_SCANNER" -eq 1 ]]; then
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

    while IFS=$'\t' read -r scenario_id family example_dir vex_path expected_purl_prefix; do
      tag="dhi-id-dhi-${scenario_id}-$$"
      build_args=(-t "$tag")
      if [[ -n "$PLATFORM" ]]; then
        build_args+=(--platform "$PLATFORM")
      fi
      build_args+=("$example_dir")

      echo "Building scanner fixture $scenario_id"
      docker build "${build_args[@]}" >/dev/null
      built_images+=("$tag")

      sbom_output="$work_dir/$scenario_id.sbom.json"
      scan_output="$work_dir/$scenario_id.scan.json"
      vex_scan_output="$work_dir/$scenario_id.scan-with-vex.json"

      scanner_sbom_json "$tag" "$sbom_output"
      python3 - "$family" "$sbom_output" "$expected_purl_prefix" <<'PY'
from __future__ import annotations

import sys
from pathlib import Path

family = sys.argv[1]
path = Path(sys.argv[2])
expected_purl_prefix = sys.argv[3]
text = path.read_text(errors="replace")
needle = "pkg:apk/dhi/" if family == "alpine" else "pkg:deb/dhi/"
if needle not in text:
    print(f"error: scanner SBOM did not contain {needle}", file=sys.stderr)
    sys.exit(1)
if expected_purl_prefix and expected_purl_prefix not in text:
    print(f"error: scanner SBOM did not contain {expected_purl_prefix}", file=sys.stderr)
    sys.exit(1)
PY

      scanner_scan_json "$tag" "$scan_output"
      if [[ "$vex_path" != "-" ]]; then
        scanner_scan_with_vex_json "$tag" "$vex_path" "$vex_scan_output"
      fi
      echo "OK: scanner-backed fixture passed for $scenario_id"
    done < <(
      python3 - "$SCENARIOS_FILE" <<'PY'
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
    observed_prefix = scenario.get("scanner_observed_package_purl_prefix")
    print("\t".join([
        scenario["id"],
        scenario["family"],
        str(example_dir),
        str(vex_path),
        observed_prefix or "",
    ]))
PY
    )
  fi
fi
