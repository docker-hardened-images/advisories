<img alt="dhi-banner" src="https://github.com/user-attachments/assets/fc0ca203-3f25-4ae5-aa8e-e3918bbcc31f" />

# DHI Scanner Integration: Upcoming Changes

**Audience**: scanner integration partners

**Status**: Draft for review and feedback

## In Brief

Docker Hardened Images (DHI) is making two changes to how images are identified
and how vulnerability data is published.

First, `/etc/os-release` will report `ID=dhi` instead of `ID=alpine` or
`ID=debian`, giving scanners an unambiguous signal that an image is a DHI image
without relying on display-string heuristics.

Second, DHI will publish an authoritative OSV feed, available through Docker's
advisory repository and planned for osv.dev ingestion, that covers DHI-owned OS
packages whose scanner-observed identities use `pkg:apk/dhi/...` and
`pkg:deb/dhi/...` PURLs.

Together, these changes let scanners produce accurate DHI OS package
vulnerability results from a positive-signal advisory feed instead of relying on
DHI VEX as the mechanism that suppresses false positives. Docker will continue
to publish VEX statements for DHI images, but consuming VEX will no longer be a
requirement for accurate DHI OS package CVE counts.

## The New Model: Positive Signal Via OSV

The DHI OSV feed becomes the authoritative source of truth for vulnerabilities
in DHI OS packages, including APK and Debian package formats. When scanning a
DHI image, use the DHI OSV feed to determine which vulnerabilities affect its
DHI OS packages. If an OS package from the image is listed in the feed as
affected and its installed version is explicitly listed in
`affected[].versions` or falls within any `affected[].ranges`, treat it as
affected. If neither representation matches, interpret that as no matching
vulnerability in the DHI context.

Publication of an official image with `ID=dhi` is the readiness signal for this
model. Docker will not publish the cutover image until generated DHI advisory
data is available for the image and its contents. Scanners do not need a
separate feed-readiness marker or fallback to current-production matching for a
published `ID=dhi` image.

For other package types found in the image or SBOM, such as language ecosystem
packages from npm, PyPI, Go, or RubyGems, scanners should continue to consult
the appropriate ecosystem-specific advisory sources. DHI-owned non-OS package
handling may receive additional scanner guidance as package ownership and
advisory routing rules are finalized.

The DHI PURL namespace is scanner-observed package identity, not proof of DHI
ownership by itself. For official images, integrations establish membership by
matching exact package and version identities against the full SPDX or
CycloneDX OCI-referrer SBOM attached to the resolved DHI platform-manifest
digest. The embedded `/opt/docker/sbom/.spdx.json` product shim and
scanner-generated inventories are not substitutes for that membership SBOM.

For derived images, integrations can establish DHI package origin using the
existing DHI chain-ID boundary and package layer attribution, or by exact
package-and-version comparison with the Docker-issued SBOM for a known DHI base
image. If a package is not attributed to DHI, normalize it to the corresponding
upstream Alpine or Debian identity and use normal upstream advisory coverage
with native APK or dpkg version semantics. Namespace alone remains insufficient
to select DHI advisory data.

DHI's internal triage workflow produces the assessments that populate the OSV
feed. The feed uses [OSV format](https://ossf.github.io/osv-schema/), the same
format already consumed by many scanner ecosystems.

Docker remains committed to transparency and will continue to publish VEX.
VEX remains useful as assessment context, especially for explaining Docker's
status, impact, and action notes for matching advisory/package products.
However, in the new model, VEX is context rather than the primary integration
mechanism required for accurate vulnerability counts.

## What Changes

### `/etc/os-release`

Today, DHI images report `ID=alpine` or `ID=debian` and rely on `PRETTY_NAME`
containing `Docker Hardened Images` as a detection heuristic. This is fragile
and requires string matching against a display field.

After cutover, DHI images report:

```text
ID=dhi
ID_LIKE=alpine   # or ID_LIKE=debian, depending on base
VERSION_ID=3.24  # or the corresponding Debian base release
```

Integration expectations:

- Detect DHI images by checking `ID=dhi`.
- Use `ID_LIKE` when the scanner needs the underlying package manager family.
- Preserve `VERSION_ID` as the base release used to partition DHI advisory
  matching.
- Do not depend on `PRETTY_NAME` for DHI detection.

### DHI OS Package PURLs

For OS packages observed under final `ID=dhi`, package PURLs generally use the
DHI namespace:

```text
pkg:apk/dhi/<package>@<apk-version>...
pkg:deb/dhi/<package>@<deb-version>...
```

The package type still matters. `pkg:apk/dhi/...` uses APK version comparison,
and `pkg:deb/dhi/...` uses Debian package version comparison. `ID_LIKE`
provides package-family context, not the advisory namespace for DHI-owned OS
packages. For derived images, DHI advisory coverage requires chain-ID/layer
attribution to the DHI base or an exact package-and-version match against the
Docker-issued SBOM for a known base image; the PURL namespace alone is not
enough.

Generated OSV affected entries use a release-scoped ecosystem variant, such as
`Docker Hardened Images:Alpine:3.24` or
`Docker Hardened Images:Debian:13`. The lineage selects the
package-manager-native ordering and the release prevents cross-release
advisory matches. Scanner PURLs with `distro=dhi-<release>` must normalize to
the same variant as canonical feed PURLs with `os_version=<release>`. These
entries can enumerate exact affected `versions`, provide native `ECOSYSTEM`
ranges, or provide both. `ECOSYSTEM` ranges must not fall back to SemVer. See
[Package identity and versioning](upcoming-id-dhi/docs/package-identity-and-versioning.md)
for the complete contract.

### DHI OSV Feed

When scanning a DHI image, query the DHI OSV feed to determine which
vulnerabilities affect DHI OS packages. Report a finding when a DHI package
version is explicitly listed in `affected[].versions` or falls within an
affected range. If neither matches, do not report a DHI finding for that
advisory/package/version.

The scanner integration guide specifies the target package identity shape and
the expected OSV/VEX relationship for the migration.

### VEX Feed

There is no planned change to the existence of DHI's VEX feed.

Integration expectations:

- VEX is no longer required to produce accurate DHI OS package CVE counts.
- If a scanner already consumes VEX and wants to continue using it for
  transparency and assessment context, that remains valid.
- VEX statements should be matched to exact product PURLs. Do not infer that a
  VEX statement for one package version applies to another package version.
- VEX statements should be consistent with the OSV feed generated from the same
  DHI assessments.

## Integration Guide Updates

The scanner integration guide is split into two model-specific sections:

- [Current production guide](current-production/README.md)
- [Upcoming `ID=dhi` guide](upcoming-id-dhi/README.md)

The current-production guide remains valid until an image family cuts over. The
upcoming `ID=dhi` guide describes the target scanner behavior for cutover
images and the generated DHI OSV/VEX model.

## Timeline

Work is ongoing. Current planning targets Summer 2026 for release. Docker will
share more specific dates as the release approaches.
