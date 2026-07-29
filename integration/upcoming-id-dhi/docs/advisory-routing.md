# Advisory Routing

The upcoming model routes DHI base-layer OS packages to generated DHI advisory
data. `ID_LIKE` identifies the Alpine or Debian package family behind the DHI
image, but it is not the advisory namespace for DHI-owned packages.

The exact ecosystem and version-dispatch contract is defined in
[Package identity and versioning](package-identity-and-versioning.md).

## Official DHI Images

For an official DHI image as published by Docker, exact package-and-version
membership in its Docker-issued SBOM establishes that an OS package is part of
the DHI product. Route those packages to DHI advisory data using the
package PURL type, lineage, release, and native version semantics described
below.

### Obtaining The Docker-Issued SBOM

The SBOM used for product membership is the full SPDX or CycloneDX attestation
attached to the official image through OCI referrers:

1. Resolve the scanned image to its platform-manifest digest.
2. List OCI referrers for that digest.
3. Select the attached SPDX or CycloneDX SBOM attestation.
4. Match scanner-observed packages to the exact package and version identities
   in that SBOM.

Attachment to the resolved DHI platform-manifest digest establishes Docker
issuance for this integration contract. Do not substitute a scanner-generated
inventory or `/opt/docker/sbom/.spdx.json`: that embedded file is a
product-level shim, not the full OS package SBOM.

If the attached SBOM is unavailable, membership is not established. Do not
apply generated DHI advisory data from the DHI PURL namespace alone.

## Routing Inputs

| Input | Meaning |
| --- | --- |
| `/etc/os-release` `ID=dhi` | The image is using the new DHI OS identity model. |
| `/etc/os-release` `ID_LIKE=alpine` or `debian` | The underlying package manager family and version semantics. |
| `/etc/os-release` `VERSION_ID` | The underlying Alpine or Debian distribution version, for example `3.24` or `13`; this release partitions the OSV ecosystem. |
| SBOM package PURL | The concrete package identity that scanner findings and VEX products must match. |
| Docker-issued SBOM | The full SPDX or CycloneDX OCI-referrer attestation attached to the resolved DHI platform-manifest digest. For an official image, it establishes membership when the exact package and version appear in the SBOM. |
| DHI chain ID and package layer attribution | For a derived image, identifies the DHI base-layer boundary and packages inherited from those layers. |
| Known DHI base SBOM | When the exact base image is known, provides another way to establish derived-image membership by exact package-and-version comparison. |

## Package Routing

| Package | Advisory routing |
| --- | --- |
| Exact `pkg:apk/dhi/<name>@<version>...` package and version in an official image's Docker-issued SBOM, or attributed to a DHI base in a derived image | Generated DHI OSV data, APK version comparison. |
| Exact `pkg:deb/dhi/<name>@<version>...` package and version in an official image's Docker-issued SBOM, or attributed to a DHI base in a derived image | Generated DHI OSV data, Debian version comparison. |
| OS package whose DHI product membership is not established | Normalize to the corresponding upstream Alpine or Debian package identity and use normal upstream advisory coverage with APK or dpkg version comparison. Do not apply generated DHI advisory data merely because the scanner emits a `pkg:apk/dhi/...` or `pkg:deb/dhi/...` PURL. |

## Derived Images

These additional checks apply when a customer or other producer adds layers to
an official DHI image. Current scanner behavior derives OS package PURLs from
the final image OS identity, so any OS package visible in an image whose
`/etc/os-release` reports `ID=dhi` can appear as `pkg:apk/dhi/...` or
`pkg:deb/dhi/...`.

That DHI PURL is the package identity to use for exact finding and VEX product
matching. It is not, by itself, proof that Docker built, shipped, or assessed
that package.

For a derived image, establish package membership using either of the existing
DHI origin checks:

1. Read `com.docker.dhi.chain-id`, calculate the image's ordered rootfs chain
   IDs, locate the matching DHI base-layer boundary, and attribute packages to
   layers at or before that boundary.
2. When the exact DHI base image is already known, retrieve its Docker-issued
   SBOM using its resolved platform-manifest digest and compare exact package
   and version identities.

The chain ID identifies a layer boundary; it is not an image digest or an OCI
referrer lookup key. If neither method establishes DHI origin, normalize the
package to the upstream family and release from `ID_LIKE` and `VERSION_ID`, then
use normal upstream Alpine or Debian advisory coverage with the native package
manager's version semantics. Do not apply generated DHI advisory data from the
package namespace alone.

The [derived-image fixture](../examples/e2e-alpine-layer-package-namespace/README.md)
demonstrates this boundary with two packages in one final `ID=dhi` image.
`coreutils` is present at the exact version in the recorded base snapshot and
its package files remain in the base-layer prefix, so it is eligible for
generated DHI OSV matching. `jq` is absent from that snapshot and its package
files come from later layers, so it is not eligible even though the scanner
emits a `pkg:apk/dhi/jq@...` PURL; it routes to normal upstream Alpine
coverage. The fixture models membership comparison and layer attribution; it
does not retrieve an OCI-referrer SBOM or verify its attachment to a
platform-manifest digest.

## Component Package Context

DHI advisories can still carry component context. For example, a DHI OS package
advisory may be matched through `pkg:apk/dhi/python-3.12@...` while referencing
an embedded language package such as `pkg:pypi/setuptools@...`. That component
PURL explains why the DHI package is in scope; it is context only and does not
replace the DHI OS package PURL as the advisory match key. If the same language
package also appears independently in the SBOM, evaluate it separately using
its ecosystem-specific advisory source and version semantics. Do not infer DHI
advisory coverage from the component relationship.

## OSV Shape

OSV records use the `DHI-` advisory ID prefix. Affected package entries use the
exact DHI ecosystem variant derived from PURL type, lineage, and release.
Package versions live in OSV ranges, not in the affected package PURL:

```json
{
  "package": {
    "ecosystem": "Docker Hardened Images:Alpine:3.24",
    "name": "coreutils",
    "purl": "pkg:apk/dhi/coreutils?os_distro=alpine&os_name=dhi&os_version=3.24"
  },
  "ranges": [
    {
      "type": "ECOSYSTEM",
      "events": [
        { "introduced": "0" },
        { "fixed": "9.11-r1" }
      ]
    }
  ]
}
```

For an `under_investigation` assessment, the generated affected entry
conservatively covers every applicable DHI package version still within the
investigation's scope. That coverage remains limited to the exact DHI package
identity, lineage, and release; it must not broaden the result to another DHI
package or base release. A scanner reports the OSV match even if it does not
consume the paired VEX record.

## Scanner-Observed PURLs

Scanner output may include scanner-specific qualifiers. Recorded pre-cutover
observations include package PURLs like:

```text
pkg:apk/dhi/coreutils@9.11-r0?arch=aarch64&distro=dhi-3.24
```

For OSV package queries, use `ID_LIKE` and `VERSION_ID` to normalize this
scanner form to the canonical feed PURL with `os_distro=alpine`,
`os_name=dhi`, and `os_version=3.24`. That normalized package identity selects
the `Docker Hardened Images:Alpine:3.24` ecosystem. VEX product matching uses
the same normalized package identity with the exact installed version retained;
see [VEX context](vex-context.md).

## Advisory Availability

Publication of an official image with `ID=dhi` is the readiness signal for the
upcoming model. Docker will not publish the cutover image until generated DHI
advisory data is available for that image and its contents. Image publication
and advisory availability are therefore atomic from the scanner integration's
perspective; scanners do not need a separate readiness marker.

For an eligible DHI package, query the release-scoped DHI ecosystem and evaluate
the package version against the generated affected ranges. If no affected range
matches, interpret the result as no matching vulnerability. Do not fall back to
current-production or upstream Alpine or Debian matching for that DHI package.
Docker publishes conservative affected coverage while an applicable assessment
is `under_investigation`, so absence of a matching range is not an unresolved
state.

Before a production image cuts over, this repository provides local fixtures
for the expected OSV and VEX shape. After cutover, scanners should use the
published DHI advisory surfaces.

The scanner-facing shape is:

```text
Official DHI image
  -> resolve platform-manifest digest
  -> retrieve attached SPDX or CycloneDX OCI-referrer SBOM
  -> pkg:(apk|deb)/dhi/... package PURLs
  -> generated DHI OSV range evaluation
  -> finding or no finding
  -> matching generated DHI VEX context for findings

Derived image
  -> establish DHI origin using chain-ID/layer attribution
     or exact comparison with a known base's Docker-issued SBOM
  -> yes: evaluate DHI OSV
  -> no: normalize to upstream Alpine or Debian identity
         and use normal upstream advisory coverage
```

This repository publishes production DHI advisory data under
[`osv/`](../../../osv/) and [`vex/`](../../../vex/). The examples and
validation checks in this guide provide local fixtures for the expected shape.
