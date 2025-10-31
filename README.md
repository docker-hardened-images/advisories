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
