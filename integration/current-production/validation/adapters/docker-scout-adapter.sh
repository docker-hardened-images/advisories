#!/usr/bin/env bash

SCANNER_NAME="${SCANNER_NAME:-docker-scout-reference}"
SCOUT_CACHE_DIR="${DOCKER_SCOUT_CACHE_DIR:-${TMPDIR:-/tmp}/dhi-scout-cache}"
TARGET_PLATFORM="${DHI_TARGET_PLATFORM:-${DHI_SCOUT_PLATFORM:-}}"
SCOUT_PLATFORM="${DHI_SCOUT_PLATFORM:-$TARGET_PLATFORM}"
mkdir -p "$SCOUT_CACHE_DIR"
export DOCKER_SCOUT_CACHE_DIR="$SCOUT_CACHE_DIR"

scout() {
  local subcommand="$1"
  shift

  if [[ -n "$SCOUT_PLATFORM" && ( "$subcommand" == "sbom" || "$subcommand" == "cves" ) ]]; then
    docker scout "$subcommand" --platform "$SCOUT_PLATFORM" "$@"
  else
    docker scout "$subcommand" "$@"
  fi
}

platform_docker_run() {
  if [[ -n "$TARGET_PLATFORM" ]]; then
    docker run --platform "$TARGET_PLATFORM" "$@"
  else
    docker run "$@"
  fi
}

scanner_sbom_list() {
  local target="$1"
  scout sbom "$target" --format list 2>/dev/null
}

scanner_sbom_json() {
  local target="$1"
  scout sbom "$target" --format json 2>/dev/null
}

scanner_cves() {
  scout cves --format packages "$@" 2>/dev/null
}

scanner_cves_with_vex() {
  local vex_file="$1"
  shift
  scout cves --format packages --vex-location "$vex_file" "$@" 2>/dev/null
}

scanner_vex_get() {
  local target="$1"
  scout vex get "$target" 2>/dev/null
}

scanner_detect_dhi() {
  local image="$1"
  local output=""

  if run_capture output platform_docker_run --rm --entrypoint python "$image" -c "print(open('/etc/os-release').read())"; then
    echo "$output" | grep -qi "Docker Hardened Images"
    return $?
  fi

  if run_capture output platform_docker_run --rm --entrypoint /bin/sh "$image" -c "cat /etc/os-release"; then
    echo "$output" | grep -qi "Docker Hardened Images"
    return $?
  fi

  return 1
}
