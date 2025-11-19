# Docker Hardened Images - Advisories

This repository contains vulnerability advisories for OSS components built and distributed with Docker Hardened
Images (DHIs), along with VEX (Vulnerability Exploitability eXchange) documents.

## Overview

Docker Hardened Images are security-focused container images that include:
- Security patches and hardening configurations
- Vulnerability tracking and advisories
- VEX statements documenting vulnerability assessments

This repository serves as the authoritative source for security information about components included in DHIs.

## Repository Structure

### OSV Advisories (`osv/`)

Vulnerability advisories in [OSV (Open Source Vulnerability)](https://ossf.github.io/osv-schema/) format,
organized by component:

```
osv/
├── aspnetcore/
├── clickhouse-server/
├── cosign/
├── envoy/
├── fluentd/
├── gradle/
├── grafana/
├── grist/
├── keycloak/
├── netdata/
├── node/
├── open-policy-agent/
├── openfga/
├── opensearch/
├── prometheus/
├── python/
├── rabbitmq/
├── redis/
├── rust/
├── spark/
├── syft/
├── tempo/
├── traefik/
├── trivy/
├── uptime-kuma/
└── valkey/
```

Each directory contains JSON files named by CVE ID (e.g., `CVE-2022-38013.json`) that follow the OSV schema and
include:
- Vulnerability details and affected version ranges
- Package information specific to DHI ecosystem
- References to upstream advisories
- Severity and impact information

### VEX Documents (`vex/`)

[OpenVEX](https://github.com/openvex/spec) statements organized by component, documenting the exploitability status
of vulnerabilities:

```
vex/
├── activemq-artemis/
├── airflow/
├── alertmanager/
├── alloy/
├── alpine-base/
└── ...
```

VEX documents provide:
- **Status assessments**: `not_affected`, `affected`, `fixed`, or `under_investigation`
- **Justifications**: Why a CVE does not impact the component
- **Status notes**: Detailed explanations and upstream references
- **Product associations**: Links vulnerabilities to specific package versions

### VEXHub Discovery (`pkg/` and `index.json`)

This repository implements the [VEX Repository Specification](https://github.com/aquasecurity/vex-repo-spec) to enable automated VEX discovery. The `pkg/` directory contains VEX documents organized by package type and repository URL, with an `index.json` file at the root for programmatic discovery.

```
pkg/
└── oci/
    └── index.docker.io/
        └── dhi/
            ├── airflow/
            │   └── dhi-airflow.vex.json
            ├── nginx/
            │   └── dhi-nginx.vex.json
            └── ...
index.json
```

The `index.json` file provides a complete catalog of all VEX documents with:
- **Package URLs (PURLs)**: Standard identifiers without version qualifiers
- **File locations**: Relative paths to VEX documents
- **Format information**: Document format (OpenVEX)
- **Last updated timestamp**: When the index was generated

Example `index.json` structure:

```json
{
  "updated_at": "2025-11-18T23:16:54Z",
  "packages": [
    {
      "id": "pkg:oci/nginx?repository_url=index.docker.io/dhi/nginx",
      "location": "oci/index.docker.io/dhi/nginx/dhi-nginx.vex.json",
      "format": "openvex"
    },
    {
      "id": "pkg:oci/airflow?repository_url=index.docker.io/dhi/airflow",
      "location": "oci/index.docker.io/dhi/airflow/dhi-airflow.vex.json",
      "format": "openvex"
    }
  ]
}
```

This structure enables:
- **Automated discovery**: Tools can read `index.json` to find all available VEX data
- **Package-specific lookups**: Find VEX documents by Package URL (PURL)
- **Integration with scanning tools**: Trivy, Grype, and other tools can automatically locate relevant VEX data
- **Version control**: Track changes to VEX availability over time

## Data Formats

### OSV Schema

Advisories use the OSV schema with DHI-specific extensions:

```json
{
  "id": "CVE-2022-38013",
  "affected": [{
    "package": {
      "ecosystem": "DHI",
      "name": "aspnetcore",
      "purl": "pkg:dhi/aspnetcore"
    },
    "ranges": [{
      "type": "SEMVER",
      "events": [
        {"introduced": "0"},
        {"fixed": "3.1.28"}
      ]
    }],
    "database_specific": {
      "source_ecosystem": "binary",
      "source_package": "Microsoft.Aspnetcore.Mvc.Abstractions.dll"
    }
  }]
}
```

### OpenVEX Format

VEX statements follow OpenVEX v0.2.0:

```json
{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "author": "Docker Hardened Images <dhi@docker.com>",
  "statements": [{
    "vulnerability": {"name": "CVE-2010-0928"},
    "products": [{
      "@id": "pkg:docker/dhi/temporalio-ui"
    }],
    "status": "not_affected",
    "justification": "vulnerable_code_cannot_be_controlled_by_adversary",
    "status_notes": "Detailed explanation..."
  }]
}
```

## Usage

### Consuming OSV Advisories

OSV advisories can be consumed by tools that support the OSV schema:
- OSV.dev
- Dependency scanning tools
- Vulnerability management platforms

### Consuming VEX Data

VEX documents can be used with tools that support OpenVEX:
- Docker Scout
- Grype with VEX support
- Trivy
- Other SBOM/vulnerability scanning tools

Example with Docker Scout:
```bash
docker scout cves --vex-location ./vex/aspnetcore/ dhi/aspnetcore:latest
```

### Discovering VEX Data Programmatically

The `index.json` file enables automated VEX discovery following the VEX Repository Specification:

**Fetch the index:**
```bash
curl -s https://raw.githubusercontent.com/docker/advisories/main/index.json | jq .
```

**Find VEX data for a specific package:**
```bash
# Search by package name
curl -s https://raw.githubusercontent.com/docker/advisories/main/index.json \
  | jq '.packages[] | select(.id | contains("nginx"))'

# Output:
# {
#   "id": "pkg:oci/nginx?repository_url=index.docker.io/dhi/nginx",
#   "location": "oci/index.docker.io/dhi/nginx/dhi-nginx.vex.json",
#   "format": "openvex"
# }
```

**Download a specific VEX document:**
```bash
# Get the location from index.json
LOCATION=$(curl -s https://raw.githubusercontent.com/docker/advisories/main/index.json \
  | jq -r '.packages[] | select(.id | contains("nginx")) | .location')

# Download the VEX document
curl -s "https://raw.githubusercontent.com/docker/advisories/main/pkg/${LOCATION}"
```

### Using VEX Data with Trivy

#### VEX Hub Repository Format

Trivy supports the [VEX Hub repository format](https://github.com/aquasecurity/vex-repo-spec), which automatically manages updates to VEX data. This is the recommended approach for consuming DHI VEX statements with Trivy.

**Configure Trivy to use the DHI VEX Hub:**

Add the DHI advisories repository to your Trivy VEX configuration file (typically `~/.trivy/vex/repository.yaml`):

```yaml
repositories:
  - name: dhi-vex
    url: https://github.com/docker-hardened-images/advisories
    enabled: true
    username: ""
    password: ""
```

**Download and update the VEX repository:**

```bash
# Download VEX data to Trivy's local cache
trivy vex repo download

# Output:
# INFO [vex] Updating repository... repo="dhi-vex" url="https://github.com/docker-hardened-images/advisories"
```

**Scan with VEX repository:**

```bash
# Scan a DHI image with VEX data applied
trivy image --scanners vuln --vex repo --show-suppressed dhi/bash:5
```

Example output showing suppressed vulnerabilities:

```
dhi/nginx:latest (debian 12.8)
Total: 0 (HIGH: 0, CRITICAL: 0)

Suppressed Vulnerabilities (Total: 5)
┌─────────────┬────────────────┬──────────┬──────────────┬─────────────────────────────────────────┬────────────────────────────────────────┐
│   Library   │ Vulnerability  │ Severity │    Status    │                Statement                │                 Source                 │
├─────────────┼────────────────┼──────────┼──────────────┼─────────────────────────────────────────┼────────────────────────────────────────┤
│ libssl3t64  │ CVE-2024-9143  │ HIGH     │ not_affected │ vulnerable_code_not_in_execute_path     │ VEX Repository: dhi-advisories         │
│             │                │          │              │                                         │ (https://github.com/docker/advisories) │
├─────────────┼────────────────┼──────────┼──────────────┼─────────────────────────────────────────┼────────────────────────────────────────┤
│ openssl     │ CVE-2024-8096  │ HIGH     │ not_affected │ vulnerable_code_cannot_be_controlled_   │ VEX Repository: dhi-advisories         │
│             │                │          │              │ by_adversary                            │ (https://github.com/docker/advisories) │
└─────────────┴────────────────┴──────────┴──────────────┴─────────────────────────────────────────┴────────────────────────────────────────┘
```

#### Standalone VEX File Usage

You can also use individual VEX files directly without configuring a repository:

```bash
# Download a specific VEX file
curl -o dhi-nginx.vex.json https://raw.githubusercontent.com/docker/advisories/main/vex/nginx/dhi-nginx.vex.json

# Scan with the VEX file
trivy image --vex dhi-nginx.vex.json --show-suppressed dhi/nginx:latest
```

Or use the consolidated VEX file for all DHI images:

```bash
# Download the consolidated VEX file containing all DHI VEX statements
curl -o dhi.vex.json https://raw.githubusercontent.com/docker/advisories/main/vex/dhi.vex.json

# Scan any DHI image with the consolidated file
trivy image --vex dhi.vex.json --show-suppressed dhi/postgres:latest
```

**Note:** When scanning Docker Hardened Images, we recommend using the VEX data from this repository as the authoritative source, since these statements are created and maintained by the DHI team.

### Verifying OSV Advisories

#### Checksums

Each OSV advisory includes SHA256 and SHA512 checksums for integrity verification. Checksum files are provided alongside the advisory documents:

```bash
# Verify SHA256 checksum
shasum -a 256 -c CVE-2022-38013.json.sha256

# Verify SHA512 checksum
shasum -a 512 -c CVE-2022-38013.json.sha512
```

#### Signature Verification with Cosign

All OSV advisories and their checksum files are signed using [Cosign](https://github.com/sigstore/cosign) for authenticity verification.

**Verify an advisory signature:**

```bash
# Install cosign (if not already installed)
# See https://docs.sigstore.dev/cosign/installation/

# Verify the advisory JSON file
cosign verify-blob \
  --bundle CVE-2022-38013.json.sig \
  --key https://registry.scout.docker.com/keyring/dhi/latest \
  CVE-2022-38013.json

# Verify the SHA256 checksum file
cosign verify-blob \
  --bundle CVE-2022-38013.json.sha256.sig \
  --key https://registry.scout.docker.com/keyring/dhi/latest \
  CVE-2022-38013.json.sha256

# Verify the SHA512 checksum file
cosign verify-blob \
  --bundle CVE-2022-38013.json.sha512.sig \
  --key https://registry.scout.docker.com/keyring/dhi/latest \
  CVE-2022-38013.json.sha512
```

Successful verification confirms:
- The advisory was signed by the Docker Hardened Images team
- The document has not been tampered with since signing

### Verifying VEX Documents

#### Checksums

Each VEX document includes SHA256 and SHA512 checksums for integrity verification. Checksum files are provided alongside the VEX documents:

```bash
# Verify SHA256 checksum
sha256sum -c dhi-aspnetcore.vex.json.sha256

# Verify SHA512 checksum
sha512sum -c dhi-aspnetcore.vex.json.sha512
```

#### Signature Verification with Cosign

All VEX documents are signed using [Cosign](https://github.com/sigstore/cosign) for authenticity verification.

**Verify a VEX document signature:**

```bash
# Install cosign (if not already installed)
# See https://docs.sigstore.dev/cosign/installation/

# Verify the signature
cosign verify-blob \
  --bundle dhi-aspnetcore.vex.json.sig \
  --key https://registry.scout.docker.com/keyring/dhi/latest \
  dhi-aspnetcore.vex.json
```

**Verifying the consolidated VEX file:**

```bash
cosign verify-blob \
  --bundle dhi.vex.json.sig \
  --key https://registry.scout.docker.com/keyring/dhi/latest \
  dhi.vex.json
```

Successful verification confirms:
- The VEX document was signed by the Docker Hardened Images team
- The document has not been tampered with since signing

## Contributing

This repository is maintained by the Docker Hardened Images team. Security advisories are generated and updated
based on:
- Upstream security advisories
- Internal security assessments
- Vulnerability scanning results
- Security research

## License

See [LICENSE](LICENSE) for details.

## Contact

For security concerns or questions about DHI advisories:
- Email: dhi@docker.com
- Documentation: [Docker Hardened Images](https://www.docker.com/products/hardened-images/)
