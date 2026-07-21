#!/usr/bin/env bash

scanner_name() {
  printf '%s\n' "docker-scout"
}

scanner_version() {
  docker scout version | awk -F': ' '/^version:/ {print "docker scout " $2}'
}

scanner_preflight() {
  command -v docker >/dev/null 2>&1 || {
    echo "docker is required for the docker scout adapter" >&2
    return 1
  }
  docker scout version >/dev/null 2>&1 || {
    echo "docker scout is required for the docker scout adapter" >&2
    return 1
  }
}

scanner_sbom_json() {
  local target="$1"
  local output="$2"
  docker scout sbom --format json --output "$output" "$target"
}

scanner_scan_json() {
  local target="$1"
  local output="$2"
  docker scout cves --format sarif --output "$output" "$target"
}

scanner_scan_with_vex_json() {
  local target="$1"
  local vex="$2"
  local output="$3"
  docker scout cves --format sarif --vex-location "$vex" --output "$output" "$target"
}
