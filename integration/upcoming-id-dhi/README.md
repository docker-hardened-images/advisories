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

## 🎯 Quick Start

1. Review [Package identity and versioning](docs/package-identity-and-versioning.md)
2. Review [Advisory routing](docs/advisory-routing.md)
3. Review [VEX context](docs/vex-context.md)
4. Use the [Decision trees](docs/decision-trees.md)
5. Try the [Alpine](examples/e2e-alpine/README.md) and
   [Debian](examples/e2e-debian/README.md) end-to-end examples
6. Validate using the [Validation harness](validation/README.md)

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
> releases. Implementations must preserve the release from the package PURL,
> use versions from the installed package database or SBOM PURL, and must not
> fall back to SemVer. See
> [Package identity and versioning](docs/package-identity-and-versioning.md).

`ID_LIKE` identifies the package manager family; it is not the advisory
namespace for DHI-owned OS packages.

Generated DHI OSV records are authoritative for DHI base-layer OS package
findings. Generated DHI VEX records provide assessment context for matching
DHI advisory/package products.

A DHI package PURL is scanner-observed package identity, not proof of DHI
product membership by itself. Scanner integrations that analyze derived images
need layer attribution, DHI base SBOM membership, provenance metadata, or
equivalent evidence before treating a package as covered by generated DHI
advisory data.

## What Changes From Current Production?

| Concern | Current production | Upcoming `ID=dhi` |
| --- | --- | --- |
| DHI detection | `ID=alpine` or `ID=debian` plus DHI-specific image evidence. | `ID=dhi` is the primary signal. |
| OS package PURLs | Usually upstream namespace, such as `pkg:apk/alpine/...`. | Generally DHI namespace, such as `pkg:apk/dhi/...`, for OS packages observed under final `ID=dhi`. |
| OSV matching | Current integration may need upstream feeds plus DHI VEX. | DHI OSV records are authoritative for DHI base-layer OS packages. |
| VEX role | Required overlay for many upstream findings. | Context attached to DHI advisory results; exact product matching remains important. |
| Upstream OSV lookup for DHI base-layer OS packages | Often part of the current model. | Not required for the DHI base-layer package identity once DHI OSV data exists. |
| Product membership | Often implicit in DHI image detection plus VEX product matching. | Required separately from the DHI PURL namespace when scanning derived images. |

## 🚀 Reference Fixtures

- **Alpine example**: [examples/e2e-alpine/](examples/e2e-alpine/README.md)
- **Debian example**: [examples/e2e-debian/](examples/e2e-debian/README.md)
- **Derived-image routing example**:
  [examples/e2e-alpine-layer-package-namespace/](examples/e2e-alpine-layer-package-namespace/README.md)
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
