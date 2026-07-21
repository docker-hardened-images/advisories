#!/usr/bin/env bash

scanner_name() {
  printf '%s\n' "grype"
}

scanner_version() {
  syft version | awk '$1 == "Version:" {print "syft " $2}'
  grype version | awk '$1 == "Version:" {print "grype " $2}'
}

scanner_database_status() {
  local status
  status="$(grype db status 2>/dev/null)" || {
    printf '%s\n' "grype-db unavailable"
    return 0
  }
  printf '%s\n' "$status" | awk '
    $1 == "Schema:" {schema = $2}
    $1 == "Built:" {built = $2}
    END {print "grype-db schema=" schema " built=" built}
  '
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
