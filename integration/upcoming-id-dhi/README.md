<img alt="dhi-banner" src="https://github.com/user-attachments/assets/fc0ca203-3f25-4ae5-aa8e-e3918bbcc31f" />

# Docker Hardened Images - Upcoming `ID=dhi` Scanner Integration Guide

Documentation and reference fixtures for integrating third-party security
scanners with Docker Hardened Images (DHI) after cutover images identify
themselves with `/etc/os-release` `ID=dhi`.

> **Work in progress:** This directory describes the upcoming model. Cutover
> will happen gradually, image by image, so scanners must continue to route
> each image according to the model it actually reports. The current production
> model is documented in
> [`../current-production`](../current-production/README.md). For a short
> overview of the upcoming scanner changes, start with the
> [one-page overview](../dhi-scanner-integration-upcoming-changes.md). This
> guide will receive further updates as the rollout progresses.

> **Pre-cutover fixture note:** The local Dockerfiles in this guide rewrite
> `/etc/os-release` to simulate the identity that cutover images will ship.
> This mutation exists only so the upcoming scanner behavior can be tested
> before those production images are published. Scanner integrations must not
> rewrite image metadata; cutover images will report `ID=dhi` themselves.

## Scope

This guide primarily describes scanning official DHI images as published by
Docker. An OS package is covered by generated DHI advisory data when its exact
package and version appear in the Docker-issued SBOM for that image. Obtain
that SBOM by resolving the image's platform-manifest digest and retrieving its
attached SPDX or CycloneDX OCI-referrer attestation.

Publication of an official image with `ID=dhi` signals that generated DHI
advisory data is available for that image and its contents. Docker does not
publish a cutover image before that data is available.

For a derived image, use the existing DHI chain-ID boundary to attribute
packages to DHI base layers, or compare exact package and version identities
with the Docker-issued SBOM for a known DHI base image. Packages whose DHI
origin cannot be established do not route to generated DHI advisory data from
their PURL namespace alone; normalize them to the corresponding upstream Alpine
or Debian identity and use normal upstream advisory coverage.

## 🎯 Quick Start

1. Review [Package identity and versioning](docs/package-identity-and-versioning.md)
2. Review [Advisory routing](docs/advisory-routing.md)
3. Review [VEX context](docs/vex-context.md)
4. Use the [Decision trees](docs/decision-trees.md)
5. Try the standalone [Alpine](examples/e2e-alpine/README.md) and
   [Debian](examples/e2e-debian/README.md) end-to-end examples
6. If you scan derived images, try the optional
   [derived-image routing example](examples/e2e-alpine-layer-package-namespace/README.md)
7. Validate using the [Validation harness](validation/README.md)

## Model Summary

Cutover images report:

```text
ID=dhi
ID_LIKE=alpine|debian
VERSION_ID=<upstream distro version>
```

For OS packages visible in the final image package database, scanner-observed
package identity generally follows the final OS identity. In cutover DHI images,
that means scanners can emit DHI package PURLs:

```text
pkg:apk/dhi/<package>@<apk-version>...
pkg:deb/dhi/<package>@<deb-version>...
```

> **Package identity contract:** The cutover changes package namespace, not
> package version semantics. Generated records use release-scoped ecosystems,
> such as `Docker Hardened Images:Alpine:3.24` for `pkg:apk/dhi/...` and
> `Docker Hardened Images:Debian:13` for `pkg:deb/dhi/...`. The lineage selects
> APK or dpkg ordering, and the release prevents matching across DHI base
> releases. Implementations must preserve the lineage and release from
> `ID_LIKE` and `VERSION_ID` in the normalized package identity, use versions
> from the installed package database or SBOM PURL, and must not fall back to
> SemVer. See
> [Package identity and versioning](docs/package-identity-and-versioning.md).

`ID_LIKE` identifies the package manager family; it is not the advisory
namespace for DHI-owned OS packages.

Generated DHI OSV records are authoritative for DHI base-layer OS package
findings. Every generated DHI advisory that Docker publishes includes a VEX
record. Docker also publishes an OSV record whenever the advisory must produce
a scanner finding; a fully `not_affected` advisory can therefore be VEX-only.
Scanners may consume generated DHI VEX records for assessment context, but VEX
consumption is not required to determine whether a finding exists.

When a DHI assessment has status `under_investigation`, Docker publishes an OSV
affected entry listing the exact package versions covered by the assessment in
`affected[].versions`. An OSV-only scanner reports each listed version as
affected. The paired VEX record conveys the `under_investigation` status and
any available notes.

A DHI package PURL is scanner-observed package identity, not proof of DHI
product membership by itself.

After product membership, lineage, and release are established, evaluate the
package version against the generated DHI OSV entry. A version is affected when
it is explicitly listed in `affected[].versions` or falls within any
`affected[].ranges`. If neither matches, the result is no matching
vulnerability; do not fall back to current-production or upstream distribution
matching for that DHI package. For an `under_investigation` assessment, the OSV
affected entry has no `affected[].ranges`, so a package version matches only if
it appears in `affected[].versions`; other unlisted versions do not match the
entry.

> **Derived images:** Treat a package as covered by generated DHI advisory data
> when chain-ID/layer attribution places it in the DHI base, or when its exact
> package and version appear in the Docker-issued SBOM for a known DHI base
> image. The DHI package namespace alone does not establish membership.
> Packages outside the DHI base use normal upstream Alpine or Debian advisory
> coverage with native APK or dpkg version semantics.

## What Changes From Current Production?

| Concern | Current production | Upcoming `ID=dhi` |
| --- | --- | --- |
| DHI detection | `ID=alpine` or `ID=debian` plus DHI-specific image evidence. | `ID=dhi` is the primary signal. |
| OS package PURLs | Usually upstream namespace, such as `pkg:apk/alpine/...`. | Generally DHI namespace, such as `pkg:apk/dhi/...`, for OS packages observed under final `ID=dhi`. |
| OSV matching | Current integration may need upstream feeds plus DHI VEX. | DHI OSV records are authoritative for DHI base-layer OS packages. |
| VEX role | Required overlay for many upstream findings. | Published assessment context attached to DHI advisory results; scanners may choose whether to consume it, and exact product matching remains important when they do. |
| Upstream OSV lookup for DHI base-layer OS packages | Often part of the current model. | Not required for the DHI base-layer package identity once DHI OSV data exists. |
| Product membership | Often implicit in DHI image detection plus VEX product matching. | For official images, established by exact package-and-version membership in the Docker-issued OCI-referrer SBOM. For derived images, established by chain-ID/layer attribution or exact comparison with a known base's Docker-issued SBOM. |

## 🚀 Reference Fixtures

### Official DHI Images

- **Alpine example**: [examples/e2e-alpine/](examples/e2e-alpine/README.md)
- **Debian example**: [examples/e2e-debian/](examples/e2e-debian/README.md)

### Derived Images

- **Derived-image routing example**:
  [examples/e2e-alpine-layer-package-namespace/](examples/e2e-alpine-layer-package-namespace/README.md)

### Validation

- **Scenario fixtures**: [examples/scenarios/](examples/scenarios/)
- **Validation harness**:
  [validation/run-fixture-suite.sh](validation/run-fixture-suite.sh)
- **Scanner adapters**: [validation/adapters/](validation/adapters/)

Run the default static validation:

```bash
integration/upcoming-id-dhi/validation/run-fixture-suite.sh
```

## 📄 Resources

- **Package identity and versioning**:
  [docs/package-identity-and-versioning.md](docs/package-identity-and-versioning.md)
- **Advisory routing**: [docs/advisory-routing.md](docs/advisory-routing.md)
- **VEX context**: [docs/vex-context.md](docs/vex-context.md)
- **Decision trees**: [docs/decision-trees.md](docs/decision-trees.md)
- **Coverage matrix**: [docs/scenarios.md](docs/scenarios.md)
- **Validation harness**: [validation/README.md](validation/README.md)
- **OSV Schema**: [https://ossf.github.io/osv-schema/](https://ossf.github.io/osv-schema/)
- **OpenVEX Spec**: [https://openvex.dev/](https://openvex.dev/)

---

**Docker Hardened Images** - Building secure containers, together.
