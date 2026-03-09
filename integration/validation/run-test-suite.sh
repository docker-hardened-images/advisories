#!/usr/bin/env bash
set -u -o pipefail

TARGET_PLATFORM_DEFAULT="linux/arm64"
BASE_IMAGE_ARM64="dhi.io/python:3.13-alpine3.23@sha256:219ee56599402640c694fd41fce8b009b6abcfc63e05d74239010024af94e9be"
BASE_IMAGE_AMD64="dhi.io/python:3.13-alpine3.23@sha256:1e85bddee4ecf6755d84cd70b8a04912d02d2440f1ff1624acca9a700c3c07d2"
VEX_IMAGE_ARM64="dhi.io/bash:5@sha256:55ca1da07f8332342db5224144e7455d68a2864645f1c1b7ee5f1324f11cce84"
VEX_IMAGE_AMD64="dhi.io/bash:5@sha256:a62c945bf730a72efafd468533b8d73478dfe30a35f408aff7928a7f2cc5c20a"
BASE_IMAGE_DEFAULT="$BASE_IMAGE_ARM64"
VEX_IMAGE_DEFAULT="$VEX_IMAGE_ARM64"
DERIVED_IMAGE_DEFAULT="test-derived-python"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DERIVED_CONTEXT_DEFAULT="$SCRIPT_DIR/../examples/python/derived-image"

BASE_IMAGE="$BASE_IMAGE_DEFAULT"
VEX_IMAGE="$VEX_IMAGE_DEFAULT"
DERIVED_IMAGE="$DERIVED_IMAGE_DEFAULT"
DERIVED_CONTEXT="$DERIVED_CONTEXT_DEFAULT"
TARGET_PLATFORM="${DHI_TARGET_PLATFORM:-$TARGET_PLATFORM_DEFAULT}"
SELECTED_LEVELS="1,2,3,4"
OUTPUT_PATH=""
SCANNER_ADAPTER_DEFAULT="$SCRIPT_DIR/adapters/docker-scout-adapter.sh"
SCANNER_ADAPTER="$SCANNER_ADAPTER_DEFAULT"
SCANNER_NAME=""
FIXTURES_DIR="$SCRIPT_DIR/fixtures"
EDGE41_DOCKERFILE="$FIXTURES_DIR/edge-4-1-dhi-builder-final-alpine-nondhi.Dockerfile"
EDGE42_DOCKERFILE="$FIXTURES_DIR/edge-4-2-replace-dhi-python-with-alpine-python.Dockerfile"
BASE_IMAGE_EXPLICIT=0
VEX_IMAGE_EXPLICIT=0
DOCKER_PLATFORM_ARGS=()

derived_built=0
edge41_built=0
edge42_built=0
BUILD_ERROR=""

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/dhi-validation.XXXXXX")"
RESULTS_NDJSON="$WORK_DIR/results.ndjson"
: > "$RESULTS_NDJSON"

EDGE41_IMAGE="dhi-validation-edge-4-1-${RANDOM}"
EDGE42_IMAGE="dhi-validation-edge-4-2-${RANDOM}"

BASE_PYTHON_CVES_OUTPUT=""
BASE_PYTHON_CVE=""
BASE_PYTHON_PURL=""
BASE_OPENSSL_CVES_OUTPUT=""
BASE_OPENSSL_CVE=""
BASE_OPENSSL_PURL=""
DERIVED_PYTHON_CVES_OUTPUT=""
DERIVED_PYTHON_CVE=""
DERIVED_PYTHON_PURL=""
DERIVED_FLASK_CVES_OUTPUT=""
DERIVED_FLASK_CVE=""

tmp_vex_file() {
  mktemp "$WORK_DIR/vex.XXXXXX"
}

cleanup() {
  if command -v docker >/dev/null 2>&1; then
    if [[ "$edge41_built" -eq 1 ]]; then
      docker image rm -f "$EDGE41_IMAGE" >/dev/null 2>&1 || true
    fi
    if [[ "$edge42_built" -eq 1 ]]; then
      docker image rm -f "$EDGE42_IMAGE" >/dev/null 2>&1 || true
    fi
  fi
  rm -rf "$WORK_DIR"
}
trap cleanup EXIT

usage() {
  cat <<'EOF'
Usage: ./run-test-suite.sh [options]

Options:
  --level N[,N...]     Run only selected levels (1,2,3,4). Example: --level 1,3
  --output PATH        Write JSON report to PATH
  --adapter PATH       Load scanner adapter file (default: validation/adapters/docker-scout-adapter.sh)
  --platform OS/ARCH   Target platform for index resolution and local fixture builds
  --base-image REF     Override base DHI image reference
  --vex-image REF      Override OCI image used to validate VEX referrer loading
  --derived-image TAG  Override local derived image tag (default: test-derived-python)
  --help               Show this help

Notes:
  - This harness loads scanner functions from an adapter file.
  - Docker Scout is the default adapter.
  - Required commands: docker and jq.
  - Integration partners can pass --adapter /path/to/adapter.sh.
  - Built-in validation image defaults are pinned to linux/arm64 manifests.
  - Passing --platform linux/amd64 switches built-in defaults to matching amd64 manifests.
  - Level 4 edge cases use deterministic fixture images because hardened bases intentionally ship with minimal runtime tooling.
EOF
}

set_default_image_refs_for_platform() {
  case "$TARGET_PLATFORM" in
    linux/arm64)
      if [[ "$BASE_IMAGE_EXPLICIT" -eq 0 ]]; then
        BASE_IMAGE="$BASE_IMAGE_ARM64"
      fi
      if [[ "$VEX_IMAGE_EXPLICIT" -eq 0 ]]; then
        VEX_IMAGE="$VEX_IMAGE_ARM64"
      fi
      ;;
    linux/amd64)
      if [[ "$BASE_IMAGE_EXPLICIT" -eq 0 ]]; then
        BASE_IMAGE="$BASE_IMAGE_AMD64"
      fi
      if [[ "$VEX_IMAGE_EXPLICIT" -eq 0 ]]; then
        VEX_IMAGE="$VEX_IMAGE_AMD64"
      fi
      ;;
    *)
      if [[ "$BASE_IMAGE_EXPLICIT" -eq 0 || "$VEX_IMAGE_EXPLICIT" -eq 0 ]]; then
        echo "error: unsupported default platform: $TARGET_PLATFORM" >&2
        echo "error: pass --base-image and --vex-image explicitly for this platform" >&2
        exit 1
      fi
      ;;
  esac
}

require_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "error: required command not found: $cmd" >&2
    exit 1
  fi
}

require_function() {
  local fn="$1"
  if ! declare -f "$fn" >/dev/null 2>&1; then
    echo "error: required adapter function not found: $fn" >&2
    exit 1
  fi
}

is_level_selected() {
  local level="$1"
  case ",$SELECTED_LEVELS," in
    *",$level,"*) return 0 ;;
    *) return 1 ;;
  esac
}

run_capture() {
  # run_capture <var_name> <command> [args...]
  local var_name="$1"
  shift
  local captured=""
  local code=0
  if captured="$($@ 2>&1)"; then
    code=0
  else
    code=$?
  fi
  printf -v "$var_name" "%s" "$captured"
  return "$code"
}

record_result() {
  local level="$1"
  local test_id="$2"
  local name="$3"
  local status="$4"
  local details="$5"

  jq -nc \
    --argjson level "$level" \
    --arg id "$test_id" \
    --arg name "$name" \
    --arg status "$status" \
    --arg details "$details" \
    '{level:$level,id:$id,name:$name,status:$status,details:$details}' >> "$RESULTS_NDJSON"

  printf "[L%s] %s %-7s %s\n" "$level" "$test_id" "$status" "$name"
  if [[ -n "$details" ]]; then
    printf "      %s\n" "$details"
  fi
}

load_scanner_adapter() {
  if [[ ! -f "$SCANNER_ADAPTER" ]]; then
    echo "error: scanner adapter not found: $SCANNER_ADAPTER" >&2
    exit 1
  fi

  # shellcheck disable=SC1090
  source "$SCANNER_ADAPTER"

  require_function scanner_sbom_list
  require_function scanner_sbom_json
  require_function scanner_cves
  require_function scanner_cves_with_vex
  require_function scanner_detect_dhi
  require_function scanner_vex_get

  if [[ -z "$SCANNER_NAME" ]]; then
    SCANNER_NAME="$(basename "$SCANNER_ADAPTER")"
  fi
}

extract_first_cve() {
  local text="$1"
  echo "$text" | grep -Eo 'CVE-[0-9]{4}-[0-9]+' | head -n1
}

extract_first_purl() {
  local text="$1"
  echo "$text" | grep -Eo '^pkg:[^[:space:]]+' | head -n1
}

purl_without_qualifiers() {
  local purl="$1"
  echo "${purl%%\?*}"
}

purl_with_version() {
  local purl="$1"
  local version="$2"
  local base="${purl%%\?*}"
  local qualifiers=""
  if [[ "$purl" == *\?* ]]; then
    qualifiers="?${purl#*\?}"
  fi
  base="${base%@*}@${version}"
  echo "${base}${qualifiers}"
}

create_openvex_file() {
  local file="$1"
  local cve="$2"
  local purl="$3"
  local notes="$4"
  jq -n \
    --arg cve "$cve" \
    --arg purl "$purl" \
    --arg notes "$notes" \
    --arg ts "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    '{
      "@context": "https://openvex.dev/ns/v0.2.0",
      "@id": ("https://validation.local/vex/" + $cve),
      "author": "dhi-validation-harness",
      "timestamp": $ts,
      "version": 1,
      "statements": [
        {
          "vulnerability": {"name": $cve},
          "products": [{"@id": $purl}],
          "status": "not_affected",
          "status_notes": $notes,
          "justification": "vulnerable_code_not_present"
        }
      ]
    }' > "$file"
}

cve_has_vex_not_affected() {
  local text="$1"
  local cve="$2"
  echo "$text" | awk -v needle="$cve" '
    BEGIN { in_block=0; found=0 }
    $0 ~ needle { in_block=1 }
    in_block && /VEX[[:space:]]*:[[:space:]]*not affected/ { found=1 }
    in_block && /^    [^[:space:]].*CVE-[0-9]{4}-[0-9]+/ && $0 !~ needle { in_block=0 }
    END { exit(found ? 0 : 1) }
  '
}

ensure_derived_image() {
  if [[ "$derived_built" -eq 1 ]]; then
    return 0
  fi

  local output=""
  if run_capture output docker build \
    "${DOCKER_PLATFORM_ARGS[@]}" \
    -t "$DERIVED_IMAGE" \
    "$DERIVED_CONTEXT"; then
    derived_built=1
    return 0
  fi

  BUILD_ERROR="$output"
  return 1
}

ensure_edge_4_1_image() {
  if [[ "$edge41_built" -eq 1 ]]; then
    return 0
  fi

  local output=""
  if run_capture output docker build \
    "${DOCKER_PLATFORM_ARGS[@]}" \
    --build-arg "BASE_IMAGE=$BASE_IMAGE" \
    -f "$EDGE41_DOCKERFILE" \
    -t "$EDGE41_IMAGE" \
    "$FIXTURES_DIR"; then
    edge41_built=1
    return 0
  fi

  BUILD_ERROR="$output"
  return 1
}

ensure_edge_4_2_image() {
  if [[ "$edge42_built" -eq 1 ]]; then
    return 0
  fi

  local output=""
  if run_capture output docker build \
    "${DOCKER_PLATFORM_ARGS[@]}" \
    --build-arg "BASE_IMAGE=$BASE_IMAGE" \
    -f "$EDGE42_DOCKERFILE" \
    -t "$EDGE42_IMAGE" \
    "$FIXTURES_DIR"; then
    edge42_built=1
    return 0
  fi

  BUILD_ERROR="$output"
  return 1
}

ensure_base_python_facts() {
  if [[ -n "$BASE_PYTHON_CVE" && -n "$BASE_PYTHON_PURL" ]]; then
    return 0
  fi

  local output=""
  if ! run_capture output scanner_cves "registry://$BASE_IMAGE" --only-package python --details; then
    BUILD_ERROR="$output"
    return 1
  fi

  BASE_PYTHON_CVES_OUTPUT="$output"
  BASE_PYTHON_CVE="$(extract_first_cve "$output")"
  BASE_PYTHON_PURL="$(extract_first_purl "$output")"
  [[ -n "$BASE_PYTHON_CVE" && -n "$BASE_PYTHON_PURL" ]]
}

ensure_base_openssl_facts() {
  if [[ -n "$BASE_OPENSSL_CVE" && -n "$BASE_OPENSSL_PURL" ]]; then
    return 0
  fi

  local output=""
  if ! run_capture output scanner_cves "registry://$BASE_IMAGE" --only-package openssl --details; then
    BUILD_ERROR="$output"
    return 1
  fi

  BASE_OPENSSL_CVES_OUTPUT="$output"
  BASE_OPENSSL_CVE="$(extract_first_cve "$output")"
  BASE_OPENSSL_PURL="$(extract_first_purl "$output")"
  [[ -n "$BASE_OPENSSL_CVE" && -n "$BASE_OPENSSL_PURL" ]]
}

ensure_derived_python_facts() {
  if [[ -n "$DERIVED_PYTHON_CVE" && -n "$DERIVED_PYTHON_PURL" ]]; then
    return 0
  fi

  if ! ensure_derived_image; then
    return 1
  fi

  local output=""
  if ! run_capture output scanner_cves "local://$DERIVED_IMAGE" --only-package python --details; then
    BUILD_ERROR="$output"
    return 1
  fi

  DERIVED_PYTHON_CVES_OUTPUT="$output"
  DERIVED_PYTHON_CVE="$(extract_first_cve "$output")"
  DERIVED_PYTHON_PURL="$(extract_first_purl "$output")"
  [[ -n "$DERIVED_PYTHON_CVE" && -n "$DERIVED_PYTHON_PURL" ]]
}

ensure_derived_flask_facts() {
  if [[ -n "$DERIVED_FLASK_CVE" ]]; then
    return 0
  fi

  if ! ensure_derived_image; then
    return 1
  fi

  local output=""
  if ! run_capture output scanner_cves "local://$DERIVED_IMAGE" --only-package flask --details; then
    BUILD_ERROR="$output"
    return 1
  fi

  DERIVED_FLASK_CVES_OUTPUT="$output"
  DERIVED_FLASK_CVE="$(extract_first_cve "$output")"
  [[ -n "$DERIVED_FLASK_CVE" ]]
}

# -----------------------------------------------------------------------------
# Requirements Traceability (R1-R4)
#
# R1: VEX loaded from OCI referrer attestation on image digest.
#   - Covered by test 1.3.
# R2: DHI scans include DHI OSV consideration for all packages.
#   - Covered by tests 2.1 and 2.2 (observable proxy assertions).
# R3: Distro package handling combines upstream routing + DHI VEX.
#   - Covered by tests 2.2 and 3.3.
# R4: Referrers use image digest; chainID is boundary classification only.
#   - Covered by tests 1.3, 3.1, and 3.2.
# -----------------------------------------------------------------------------

# -----------------------------------------------------------------------------
# Level 1 tests
# -----------------------------------------------------------------------------

run_test_1_1() {
  local output=""
  if run_capture output scanner_detect_dhi "$BASE_IMAGE"; then
    record_result 1 "1.1" "Identify DHI image" "passed" "Detected Docker Hardened Images marker in /etc/os-release."
  else
    record_result 1 "1.1" "Identify DHI image" "failed" "Failed to detect DHI marker."
  fi
}

run_test_1_2() {
  local output=""

  if ! run_capture output scanner_sbom_json "registry://$BASE_IMAGE"; then
    record_result 1 "1.2" "Retrieve SBOM" "failed" "SBOM command failed: ${output:-<none>}"
    return
  fi

  if echo "$output" | jq -e '(.artifacts | map(.purl // "") | any(startswith("pkg:dhi/python@"))) and (.artifacts | map(.purl // "") | any(startswith("pkg:apk/alpine/musl@")))' >/dev/null; then
    record_result 1 "1.2" "Retrieve SBOM" "passed" "Found representative DHI and APK packages in SBOM output."
  else
    record_result 1 "1.2" "Retrieve SBOM" "failed" "Did not find expected DHI/APK package markers in SBOM output."
  fi
}

run_test_1_3() {
  local output=""

  if ! run_capture output scanner_vex_get "registry://$VEX_IMAGE"; then
    record_result 1 "1.3" "Load and parse VEX referrer attestation" "failed" "VEX retrieval failed for $VEX_IMAGE: ${output:-<none>}"
    return
  fi

  if echo "$output" | jq -e '."@context" == "https://openvex.dev/ns/v0.2.0" and (.statements | type == "array") and ((.statements | length) > 0)' >/dev/null; then
    record_result 1 "1.3" "Load and parse VEX referrer attestation" "passed" "Loaded OpenVEX attestation from OCI referrer and parsed statements."
  else
    record_result 1 "1.3" "Load and parse VEX referrer attestation" "failed" "VEX output was not a valid OpenVEX document with statements."
  fi
}

run_test_1_4() {
  local with_vex_output=""
  local vex_file=""

  if ! ensure_base_python_facts; then
    record_result 1 "1.4" "Apply basic VEX" "failed" "Could not establish baseline Python CVE/PURL from base image."
    return
  fi

  vex_file="$(tmp_vex_file)"
  create_openvex_file "$vex_file" "$BASE_PYTHON_CVE" "$BASE_PYTHON_PURL" "Validation fixture for base Python package"

  if ! run_capture with_vex_output scanner_cves_with_vex "$vex_file" "registry://$BASE_IMAGE" --only-package python --details; then
    record_result 1 "1.4" "Apply basic VEX" "failed" "CVE command with VEX failed: ${with_vex_output:-<none>}"
    return
  fi

  if cve_has_vex_not_affected "$with_vex_output" "$BASE_PYTHON_CVE"; then
    record_result 1 "1.4" "Apply basic VEX" "passed" "CVE $BASE_PYTHON_CVE is marked not_affected by VEX for $BASE_PYTHON_PURL."
  else
    record_result 1 "1.4" "Apply basic VEX" "failed" "Expected VEX not_affected status for $BASE_PYTHON_CVE was not present."
  fi
}

# -----------------------------------------------------------------------------
# Level 2 tests
# -----------------------------------------------------------------------------

run_test_2_1() {
  local output=""

  if ! run_capture output scanner_cves "registry://$BASE_IMAGE" --only-package python --details; then
    record_result 2 "2.1" "Route DHI package to DHI OSV source" "failed" "CVE command failed: ${output:-<none>}"
    return
  fi

  if echo "$output" | grep -q 'pkg:dhi/python' && echo "$output" | grep -q 't=dhi'; then
    record_result 2 "2.1" "Route DHI package to DHI OSV source" "passed" "Found DHI package and DHI source marker in vulnerability output."
  else
    record_result 2 "2.1" "Route DHI package to DHI OSV source" "failed" "Did not find expected DHI routing markers in output."
  fi
}

run_test_2_2() {
  local output=""
  local with_vex_output=""
  local vex_file=""

  if ! ensure_base_openssl_facts; then
    record_result 2 "2.2" "Route distro package with upstream+VEX" "failed" "Could not establish baseline OpenSSL CVE/PURL from base image."
    return
  fi

  output="$BASE_OPENSSL_CVES_OUTPUT"
  if ! (echo "$output" | grep -q 'pkg:apk/alpine/openssl' && echo "$output" | grep -q 's=alpine'); then
    record_result 2 "2.2" "Route distro package with upstream+VEX" "failed" "Did not find expected Alpine upstream routing markers in output."
    return
  fi

  vex_file="$(tmp_vex_file)"
  create_openvex_file "$vex_file" "$BASE_OPENSSL_CVE" "$BASE_OPENSSL_PURL" "Validation fixture for distro package"

  if ! run_capture with_vex_output scanner_cves_with_vex "$vex_file" "registry://$BASE_IMAGE" --only-package openssl --details; then
    record_result 2 "2.2" "Route distro package with upstream+VEX" "failed" "CVE command with VEX failed: ${with_vex_output:-<none>}"
    return
  fi

  if cve_has_vex_not_affected "$with_vex_output" "$BASE_OPENSSL_CVE"; then
    record_result 2 "2.2" "Route distro package with upstream+VEX" "passed" "Found Alpine upstream routing and VEX application for $BASE_OPENSSL_CVE (observable R2/R3 behavior)."
  else
    record_result 2 "2.2" "Route distro package with upstream+VEX" "failed" "Upstream routing found, but VEX status was not applied for $BASE_OPENSSL_CVE."
  fi
}

run_test_2_3() {
  local output=""
  if ! ensure_derived_image; then
    record_result 2 "2.3" "Route app package to standard sources" "failed" "Could not build derived image: ${BUILD_ERROR:-<none>}"
    return
  fi

  if ! run_capture output scanner_cves "local://$DERIVED_IMAGE" --only-package flask --details; then
    record_result 2 "2.3" "Route app package to standard sources" "failed" "CVE command failed: ${output:-<none>}"
    return
  fi

  if echo "$output" | grep -q 'pkg:pypi/flask' && echo "$output" | grep -q 't=pypi'; then
    record_result 2 "2.3" "Route app package to standard sources" "passed" "Found pypi package and pypi source markers."
  else
    record_result 2 "2.3" "Route app package to standard sources" "failed" "Did not find expected pypi routing markers."
  fi
}

# -----------------------------------------------------------------------------
# Level 3 tests
# -----------------------------------------------------------------------------

run_test_3_1() {
  local output=""
  if ! ensure_derived_image; then
    record_result 3 "3.1" "Detect derived image by chain-id label" "failed" "Could not build derived image: ${BUILD_ERROR:-<none>}"
    return
  fi

  if run_capture output docker inspect "$DERIVED_IMAGE"; then
    if echo "$output" | grep -q 'com.docker.dhi.chain-id'; then
      record_result 3 "3.1" "Detect derived image by chain-id label" "passed" "Found com.docker.dhi.chain-id label."
    else
      record_result 3 "3.1" "Detect derived image by chain-id label" "failed" "chain-id label not present."
    fi
  else
    record_result 3 "3.1" "Detect derived image by chain-id label" "failed" "docker inspect failed: ${output:-<none>}"
  fi
}

run_test_3_2() {
  local output=""

  if ! ensure_derived_image; then
    record_result 3 "3.2" "Classify base vs customer package boundary" "failed" "Could not build derived image: ${BUILD_ERROR:-<none>}"
    return
  fi

  if ! run_capture output scanner_sbom_json "local://$DERIVED_IMAGE"; then
    record_result 3 "3.2" "Classify base vs customer package boundary" "failed" "SBOM command failed: ${output:-<none>}"
    return
  fi

  if echo "$output" | jq -e '(.artifacts | map(.purl // "") | any(startswith("pkg:dhi/python@"))) and (.artifacts | map(.purl // "") | any(startswith("pkg:pypi/flask@")))' >/dev/null; then
    record_result 3 "3.2" "Classify base vs customer package boundary" "passed" "Detected both DHI base and customer pypi packages (chainID boundary classification behavior)."
  else
    record_result 3 "3.2" "Classify base vs customer package boundary" "failed" "Could not confirm base/customer package split from SBOM output."
  fi
}

run_test_3_3() {
  local python_with_vex_output=""
  local flask_with_vex_output=""
  local vex_file=""

  if ! ensure_derived_python_facts; then
    record_result 3 "3.3" "Apply VEX only to base packages" "failed" "Could not establish derived Python CVE/PURL baseline."
    return
  fi

  if ! ensure_derived_flask_facts; then
    record_result 3 "3.3" "Apply VEX only to base packages" "failed" "Could not establish derived Flask CVE baseline."
    return
  fi

  vex_file="$(tmp_vex_file)"
  create_openvex_file "$vex_file" "$DERIVED_PYTHON_CVE" "$DERIVED_PYTHON_PURL" "Validation fixture for base package in derived image"

  if ! run_capture python_with_vex_output scanner_cves_with_vex "$vex_file" "local://$DERIVED_IMAGE" --only-package python --details; then
    record_result 3 "3.3" "Apply VEX only to base packages" "failed" "CVE command for base package with VEX failed: ${python_with_vex_output:-<none>}"
    return
  fi

  if ! run_capture flask_with_vex_output scanner_cves_with_vex "$vex_file" "local://$DERIVED_IMAGE" --only-package flask --details; then
    record_result 3 "3.3" "Apply VEX only to base packages" "failed" "CVE command for customer package with VEX failed: ${flask_with_vex_output:-<none>}"
    return
  fi

  if cve_has_vex_not_affected "$python_with_vex_output" "$DERIVED_PYTHON_CVE" \
     && echo "$flask_with_vex_output" | grep -Eq 'CVE-[0-9]{4}-[0-9]+' \
     && ! echo "$flask_with_vex_output" | grep -q 'VEX[[:space:]]*:'; then
    record_result 3 "3.3" "Apply VEX only to base packages" "passed" "Base Python CVE was marked by VEX while customer Flask CVEs remained unsuppressed."
  else
    record_result 3 "3.3" "Apply VEX only to base packages" "failed" "Expected base-only VEX behavior was not observed in derived-image CVE output."
  fi
}

# -----------------------------------------------------------------------------
# Level 4 tests
# -----------------------------------------------------------------------------

run_test_4_1() {
  local inspect_output=""
  local sbom_output=""
  local dhi_detect_output=""

  if ! ensure_edge_4_1_image; then
    record_result 4 "4.1" "Multi-stage build edge case" "failed" "Could not build edge-case image: ${BUILD_ERROR:-<none>}"
    return
  fi

  if ! run_capture inspect_output docker inspect "$EDGE41_IMAGE"; then
    record_result 4 "4.1" "Multi-stage build edge case" "failed" "docker inspect failed: ${inspect_output:-<none>}"
    return
  fi

  if echo "$inspect_output" | grep -q 'com.docker.dhi.chain-id'; then
    record_result 4 "4.1" "Multi-stage build edge case" "failed" "Final image still carries DHI chain-id label."
    return
  fi

  if run_capture dhi_detect_output scanner_detect_dhi "$EDGE41_IMAGE"; then
    record_result 4 "4.1" "Multi-stage build edge case" "failed" "Final image still identified as DHI."
    return
  fi

  if ! run_capture sbom_output scanner_sbom_list "local://$EDGE41_IMAGE"; then
    record_result 4 "4.1" "Multi-stage build edge case" "failed" "SBOM command failed: ${sbom_output:-<none>}"
    return
  fi

  if echo "$sbom_output" | grep -q 'pkg:dhi/'; then
    record_result 4 "4.1" "Multi-stage build edge case" "failed" "Final image SBOM still contains DHI package entries."
  else
    record_result 4 "4.1" "Multi-stage build edge case" "passed" "Final stage is treated as non-DHI image with no DHI packages."
  fi
}

run_test_4_2() {
  local sbom_json=""
  local dhi_python_purl=""
  local apk_python_purl=""

  if ! ensure_edge_4_2_image; then
    record_result 4 "4.2" "Replaced DHI package edge case" "failed" "Could not build edge-case image: ${BUILD_ERROR:-<none>}"
    return
  fi

  if ! run_capture sbom_json scanner_sbom_json "local://$EDGE42_IMAGE"; then
    record_result 4 "4.2" "Replaced DHI package edge case" "failed" "SBOM command failed: ${sbom_json:-<none>}"
    return
  fi

  dhi_python_purl="$(echo "$sbom_json" | jq -r '.artifacts[] | select(.purl? | startswith("pkg:dhi/python@")) | .purl' | head -n1)"
  apk_python_purl="$(echo "$sbom_json" | jq -r '.artifacts[] | select(.purl? | startswith("pkg:apk/alpine/python3@")) | .purl' | head -n1)"

  if [[ -z "$apk_python_purl" ]]; then
    record_result 4 "4.2" "Replaced DHI package edge case" "failed" "Did not detect replacement apk Python package in fixture image."
    return
  fi

  if [[ -n "$dhi_python_purl" ]]; then
    record_result 4 "4.2" "Replaced DHI package edge case" "failed" "DHI Python package marker still present after replacement: $dhi_python_purl"
  else
    record_result 4 "4.2" "Replaced DHI package edge case" "passed" "Detected replacement package purl ($apk_python_purl) and no remaining DHI Python package marker."
  fi
}

run_test_4_3() {
  local mismatch_output=""
  local vex_file=""
  local mismatched_purl=""

  if ! ensure_base_python_facts; then
    record_result 4 "4.3" "Version mismatch edge case" "failed" "Could not establish baseline Python CVE/PURL from base image."
    return
  fi

  mismatched_purl="$(purl_with_version "$BASE_PYTHON_PURL" "0.0.0")"
  vex_file="$(tmp_vex_file)"
  create_openvex_file "$vex_file" "$BASE_PYTHON_CVE" "$mismatched_purl" "Intentional version mismatch fixture"

  if ! run_capture mismatch_output scanner_cves_with_vex "$vex_file" "registry://$BASE_IMAGE" --only-package python --details; then
    record_result 4 "4.3" "Version mismatch edge case" "failed" "CVE command with mismatch VEX failed: ${mismatch_output:-<none>}"
    return
  fi

  if cve_has_vex_not_affected "$mismatch_output" "$BASE_PYTHON_CVE"; then
    record_result 4 "4.3" "Version mismatch edge case" "failed" "Mismatched-version VEX unexpectedly applied to $BASE_PYTHON_CVE."
  else
    record_result 4 "4.3" "Version mismatch edge case" "passed" "VEX statement with mismatched package version did not apply."
  fi
}

run_test_4_4() {
  local output=""

  if ! run_capture output scanner_cves "registry://$VEX_IMAGE" --only-package bash --details; then
    record_result 4 "4.4" "Missing OSV directory edge case" "failed" "CVE command failed for bash package scenario: ${output:-<none>}"
    return
  fi

  if echo "$output" | grep -qi 'cannot determine'; then
    record_result 4 "4.4" "Missing OSV directory edge case" "failed" "Scanner reported indeterminate vulnerability state for missing-OSV scenario."
    return
  fi

  if echo "$output" | grep -q 'No vulnerable packages detected'; then
    record_result 4 "4.4" "Missing OSV directory edge case" "passed" "Missing-OSV scenario is handled as no active vulnerabilities instead of indeterminate failure."
  else
    record_result 4 "4.4" "Missing OSV directory edge case" "failed" "Expected ""No vulnerable packages detected"" signal was not present."
  fi
}

run_test_4_5() {
  local plain_vex_file=""
  local qual_vex_file=""
  local plain_output=""
  local qual_output=""
  local plain_purl=""

  if ! ensure_base_openssl_facts; then
    record_result 4 "4.5" "PURL variation edge case" "failed" "Could not establish baseline OpenSSL CVE/PURL from base image."
    return
  fi

  plain_purl="$(purl_without_qualifiers "$BASE_OPENSSL_PURL")"

  plain_vex_file="$(tmp_vex_file)"
  create_openvex_file "$plain_vex_file" "$BASE_OPENSSL_CVE" "$plain_purl" "Unqualified purl variant"

  qual_vex_file="$(tmp_vex_file)"
  create_openvex_file "$qual_vex_file" "$BASE_OPENSSL_CVE" "$BASE_OPENSSL_PURL" "Qualified purl variant"

  if ! run_capture plain_output scanner_cves_with_vex "$plain_vex_file" "registry://$BASE_IMAGE" --only-package openssl --details; then
    record_result 4 "4.5" "PURL variation edge case" "failed" "CVE command failed for unqualified purl variant: ${plain_output:-<none>}"
    return
  fi

  if ! run_capture qual_output scanner_cves_with_vex "$qual_vex_file" "registry://$BASE_IMAGE" --only-package openssl --details; then
    record_result 4 "4.5" "PURL variation edge case" "failed" "CVE command failed for qualified purl variant: ${qual_output:-<none>}"
    return
  fi

  if cve_has_vex_not_affected "$plain_output" "$BASE_OPENSSL_CVE" && cve_has_vex_not_affected "$qual_output" "$BASE_OPENSSL_CVE"; then
    record_result 4 "4.5" "PURL variation edge case" "passed" "Both qualified and unqualified purl forms matched the same VEX statement target."
  else
    record_result 4 "4.5" "PURL variation edge case" "failed" "At least one purl variant failed to match expected VEX application."
  fi
}

run_level_1() { run_test_1_1; run_test_1_2; run_test_1_3; run_test_1_4; }
run_level_2() { run_test_2_1; run_test_2_2; run_test_2_3; }
run_level_3() { run_test_3_1; run_test_3_2; run_test_3_3; }
run_level_4() { run_test_4_1; run_test_4_2; run_test_4_3; run_test_4_4; run_test_4_5; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --level)
      if [[ $# -lt 2 ]]; then
        echo "error: --level requires a value" >&2
        exit 1
      fi
      SELECTED_LEVELS="$2"
      shift 2
      ;;
    --output)
      if [[ $# -lt 2 ]]; then
        echo "error: --output requires a path" >&2
        exit 1
      fi
      OUTPUT_PATH="$2"
      shift 2
      ;;
    --adapter)
      if [[ $# -lt 2 ]]; then
        echo "error: --adapter requires a path" >&2
        exit 1
      fi
      SCANNER_ADAPTER="$2"
      shift 2
      ;;
    --platform)
      if [[ $# -lt 2 ]]; then
        echo "error: --platform requires a value" >&2
        exit 1
      fi
      TARGET_PLATFORM="$2"
      shift 2
      ;;
    --base-image)
      if [[ $# -lt 2 ]]; then
        echo "error: --base-image requires a value" >&2
        exit 1
      fi
      BASE_IMAGE="$2"
      BASE_IMAGE_EXPLICIT=1
      shift 2
      ;;
    --vex-image)
      if [[ $# -lt 2 ]]; then
        echo "error: --vex-image requires a value" >&2
        exit 1
      fi
      VEX_IMAGE="$2"
      VEX_IMAGE_EXPLICIT=1
      shift 2
      ;;
    --derived-image)
      if [[ $# -lt 2 ]]; then
        echo "error: --derived-image requires a value" >&2
        exit 1
      fi
      DERIVED_IMAGE="$2"
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "error: unknown argument: $1" >&2
      usage
      exit 1
      ;;
  esac
done

require_cmd docker
require_cmd jq
if [[ -z "$TARGET_PLATFORM" ]]; then
  echo "error: target platform must not be empty" >&2
  exit 1
fi
set_default_image_refs_for_platform
DOCKER_PLATFORM_ARGS=(--platform "$TARGET_PLATFORM")
export DHI_TARGET_PLATFORM="$TARGET_PLATFORM"
export DHI_SCOUT_PLATFORM="$TARGET_PLATFORM"
if [[ ! -f "$EDGE41_DOCKERFILE" ]]; then
  echo "error: missing fixture Dockerfile: $EDGE41_DOCKERFILE" >&2
  exit 1
fi
if [[ ! -f "$EDGE42_DOCKERFILE" ]]; then
  echo "error: missing fixture Dockerfile: $EDGE42_DOCKERFILE" >&2
  exit 1
fi
load_scanner_adapter

echo "Running DHI scanner integration checks with adapter: $SCANNER_NAME"
echo "Adapter file: $SCANNER_ADAPTER"
echo "Target platform: $TARGET_PLATFORM"
echo "Base image: $BASE_IMAGE"
echo "VEX image: $VEX_IMAGE"
echo "Derived image tag: $DERIVED_IMAGE"
echo

if is_level_selected 1; then run_level_1; fi
if is_level_selected 2; then run_level_2; fi
if is_level_selected 3; then run_level_3; fi
if is_level_selected 4; then run_level_4; fi

summary_json="$(
  jq -n \
    --slurpfile tests "$RESULTS_NDJSON" \
    '
    def stats($lvl):
      {
        passed: ($tests | map(select(.level == $lvl and .status == "passed")) | length),
        failed: ($tests | map(select(.level == $lvl and .status == "failed")) | length)
      };
    {
      level_1: stats(1),
      level_2: stats(2),
      level_3: stats(3),
      level_4: stats(4)
    }'
)"

level1_pass="$(echo "$summary_json" | jq -r '.level_1.passed')"
level1_fail="$(echo "$summary_json" | jq -r '.level_1.failed')"
level2_pass="$(echo "$summary_json" | jq -r '.level_2.passed')"
level2_fail="$(echo "$summary_json" | jq -r '.level_2.failed')"
level3_pass="$(echo "$summary_json" | jq -r '.level_3.passed')"
level3_fail="$(echo "$summary_json" | jq -r '.level_3.failed')"
level4_pass="$(echo "$summary_json" | jq -r '.level_4.passed')"
level4_fail="$(echo "$summary_json" | jq -r '.level_4.failed')"

total_fail=$((level1_fail + level2_fail + level3_fail + level4_fail))

overall="PASS"
if [[ "$total_fail" -gt 0 ]]; then
  overall="FAIL"
fi

certification_eligible="false"
if [[ "$level1_fail" -eq 0 && "$level2_fail" -eq 0 && "$level3_pass" -ge 2 ]]; then
  certification_eligible="true"
fi

report_json="$(
  jq -n \
    --arg scanner "$SCANNER_NAME" \
    --arg test_date "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --arg overall "$overall" \
    --argjson certification_eligible "$certification_eligible" \
    --argjson results "$summary_json" \
    --slurpfile tests "$RESULTS_NDJSON" \
    '{
      scanner: $scanner,
      test_date: $test_date,
      results: $results,
      overall: $overall,
      certification_eligible: $certification_eligible,
      tests: $tests
    }'
)"

echo
echo "Summary:"
echo "  Level 1 -> pass:$level1_pass fail:$level1_fail"
echo "  Level 2 -> pass:$level2_pass fail:$level2_fail"
echo "  Level 3 -> pass:$level3_pass fail:$level3_fail"
echo "  Level 4 -> pass:$level4_pass fail:$level4_fail"
echo "  Overall -> $overall"

if [[ -n "$OUTPUT_PATH" ]]; then
  echo "$report_json" | jq '.' > "$OUTPUT_PATH"
  echo
  echo "Wrote report to $OUTPUT_PATH"
else
  echo
  echo "$report_json" | jq '.'
fi
