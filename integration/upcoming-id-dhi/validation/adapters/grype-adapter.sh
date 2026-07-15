#!/usr/bin/env bash

scanner_name() {
  printf '%s\n' "grype"
}

scanner_preflight() {
  command -v syft >/dev/null 2>&1 || {
    echo "syft is required for the grype adapter" >&2
    return 1
  }
  command -v grype >/dev/null 2>&1 || {
    echo "grype is required for the grype adapter" >&2
    return 1
  }
}

scanner_sbom_json() {
  local target="$1"
  local output="$2"
  syft -q "$target" -o "json=$output"
}

scanner_scan_json() {
  local target="$1"
  local output="$2"
  grype -q "$target" -o "json=$output"
}

scanner_scan_with_vex_json() {
  local target="$1"
  local vex="$2"
  local output="$3"
  grype -q "$target" --vex "$vex" -o "json=$output"
}
