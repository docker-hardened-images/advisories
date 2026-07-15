# Advisory Routing

The upcoming model routes DHI base-layer OS packages to generated DHI advisory
data. `ID_LIKE` identifies the Alpine or Debian package family behind the DHI
image, but it is not the advisory namespace for DHI-owned packages.

## Routing Inputs

| Input | Meaning |
| --- | --- |
| `/etc/os-release` `ID=dhi` | The image is using the new DHI OS identity model. |
| `/etc/os-release` `ID_LIKE=alpine` or `debian` | The underlying package manager family and version semantics. |
| `/etc/os-release` `VERSION_ID` | The underlying Alpine or Debian distribution version, for example `3.24` or `13`. |
| SBOM package PURL | The concrete package identity that scanner findings and VEX products must match. |
| Product membership or provenance | Evidence that a scanner-observed DHI package PURL is part of a DHI-assessed product, such as DHI base SBOM membership, layer attribution, or equivalent scanner provenance. |

## Package Routing

| Package | Advisory routing |
| --- | --- |
| DHI-owned `pkg:apk/dhi/<name>@<version>...` with product membership evidence | Generated DHI OSV data, APK version comparison. |
| DHI-owned `pkg:deb/dhi/<name>@<version>...` with product membership evidence | Generated DHI OSV data, Debian version comparison. |
| Non-DHI-owned OS package observed as `pkg:apk/dhi/...` or `pkg:deb/dhi/...` | Do not apply generated DHI advisory data from PURL namespace alone. Use package provenance, DHI base SBOM membership, or equivalent product membership checks. |
| Language ecosystem package PURL referenced by a DHI OS package advisory | Component context only; the scanner match key remains the DHI OS package PURL. |

## Package Namespace And Product Membership

The scanner-observed package namespace is not enough to decide advisory
coverage. Current scanner behavior derives OS package PURLs from the final image
OS identity, so an OS package visible in an image whose `/etc/os-release`
reports `ID=dhi` can appear as `pkg:apk/dhi/...` or `pkg:deb/dhi/...`.

That DHI PURL is the package identity to use for exact finding and VEX product
matching. It is not, by itself, proof that Docker built, shipped, or assessed
that package. Generated DHI OSV and VEX data applies to DHI product packages.
Derived-image integrations need layer attribution, DHI base SBOM membership,
package provenance, or equivalent product membership evidence before applying
generated DHI advisory data.

DHI advisories can still carry component context. For example, a DHI OS package
advisory may be matched through `pkg:apk/dhi/python-3.12@...` while referencing
an embedded language package such as `pkg:pypi/setuptools@...`. That component
PURL explains why the DHI package is in scope; it does not replace the DHI OS
package PURL as the advisory match key. Direct include/exclude behavior for
language ecosystem packages that also appear independently in an SBOM requires
separate package ownership guidance.

## OSV Shape

OSV records use the `DHI-` advisory ID prefix. Affected package entries use the
schema ecosystem name `Docker Hardened Images` and a DHI package PURL. Versions
live in OSV ranges, not in the affected package PURL:

```json
{
  "package": {
    "ecosystem": "Docker Hardened Images",
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

## Scanner-Observed PURLs

Scanner output may include scanner-specific qualifiers. The cutover tooling in
`definitions/test/dhi-os-release-migration` observed Grype/Syft package PURLs
like:

```text
pkg:apk/dhi/coreutils@9.11-r0?arch=aarch64&distro=dhi-3.24
```

Generated OSV/VEX output and scanner integrations need an explicit
canonicalization rule, or VEX products need to use the scanner-observed PURL for
exact matching. The validation harness keeps that as a visible check instead of
assuming qualifier differences are harmless.

## Advisory Availability

Before production generated DHI advisory data is live, this repository provides
local fixtures for the expected OSV and VEX shape. After cutover, scanners should
use the published DHI advisory surfaces for generated DHI OSV and VEX data.

The scanner-facing shape is:

```text
DHI image SBOM
  -> pkg:(apk|deb)/dhi/... package PURLs
  -> DHI product membership or provenance check
  -> generated DHI OSV range evaluation
  -> finding or no finding
  -> matching generated DHI VEX context for findings
```

This repository does not publish production advisory data. It only provides
fixtures and validation checks for the expected shape.
