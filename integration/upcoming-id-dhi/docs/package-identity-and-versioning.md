# Package Identity and Versioning

The `ID=dhi` cutover changes how DHI operating-system packages are namespaced.
It does not replace the package manager's version grammar or ordering.

This document defines the target package identity and version contract for
generated DHI OSV records and scanner integrations. The contract applies after
an image has cut over to `/etc/os-release` `ID=dhi`. A possible change to the
public PURLs is described in [Proposed public PURL projection](#proposed-public-purl-projection-not-adopted);
the contract and examples above that section remain the current plan.

## Contract

| Base lineage and release | OSV ecosystem | OSV package PURL | Installed package PURL | Version comparison |
| --- | --- | --- | --- | --- |
| Alpine 3.24 | `Docker Hardened Images:Alpine:3.24` | `pkg:apk/dhi/<name>?os_distro=alpine&os_name=dhi&os_version=3.24` | `pkg:apk/dhi/<name>@<version>?...` | APK |
| Debian 13 | `Docker Hardened Images:Debian:13` | `pkg:deb/dhi/<name>?os_distro=debian&os_name=dhi&os_version=13` | `pkg:deb/dhi/<name>@<version>?...` | Debian/dpkg |

Generated DHI OSV records enumerate affected versions and include `ECOSYSTEM`
ranges when the assessment defines an affected interval. A version is affected
if it is listed in `affected[].versions` or falls within any
`affected[].ranges`, matching the
[OSV evaluation algorithm](https://ossf.github.io/osv-schema/#affected-fields).
The ecosystem suffix has two roles:

- `Alpine` or `Debian` selects the package lineage and native comparator;
- the final segment, such as `3.24` or `13`, partitions matching by base
  release.

## Image And Package Identity

Cutover images report:

```text
ID=dhi
ID_LIKE=alpine   # or debian
VERSION_ID=<underlying distribution version>
```

`ID=dhi` identifies the image as DHI. `ID_LIKE` and `VERSION_ID` supply the
base lineage and release. Scanners carry those values into the normalized
package identity as `os_distro` and `os_version`. The package PURL type,
lineage, and release then select the release-scoped OSV ecosystem and native
version comparator.

## Native Version Semantics

### APK

DHI APK packages retain native APK version semantics. Current DHI `coreutils`
definitions read `pkgver` and `pkgrel` from Alpine's `APKBUILD`; `pkgver=9.11`
and `pkgrel=0` produce installed version `9.11-r0`. `pkgrel` is APK's package
release number, not a DHI-specific suffix.

APK ordering must determine that:

```text
9.11-r0 < 9.11-r1
```

Implementations must also preserve APK's native handling of pre-release
markers and `pkgrel`. These versions must not be interpreted as SemVer.

### Debian

DHI Debian packages retain native dpkg version semantics. Debian-source-derived
DHI definitions commonly append a DHI package-release suffix, `+dhiN`, to the
Debian version. Current `coreutils` appends `+dhi3` to Debian version `9.7-3`,
producing installed version `9.7-3+dhi3`. Not every DHI Debian package uses
this convention, so consumers must implement complete dpkg version semantics
rather than depend on this suffix.

Debian ordering must handle the complete `[epoch:]upstream-version[-revision]`
shape, including `~`, Debian revisions, and DHI package-release suffixes such
as `+dhiN`. For example:

```text
9.7-3 < 9.7-3+dhi1 < 9.7-3+dhi3
```

## Matching Process

For each scanner-observed OS package:

1. Establish DHI product membership. For an official image, confirm that the
   exact package and version appear in the Docker-issued OCI-referrer SBOM. For
   a derived image, use DHI chain-ID/layer attribution or exact comparison with
   a verified Docker-issued base SBOM resolved through the shared
   [derived-image base-discovery procedure](../../derived-image-base-discovery.md).
   If membership is not established, normalize the package to the upstream
   family and release from `ID_LIKE` and `VERSION_ID`, use normal upstream
   advisory coverage with native APK or dpkg version semantics, and stop this
   DHI matching process.
2. Parse the PURL and require namespace `dhi`.
3. Read the base lineage and release from `ID_LIKE` and `VERSION_ID`.
4. Require PURL type `apk` for Alpine or `deb` for Debian.
5. Normalize the query PURL with `os_name=dhi`, the corresponding `os_distro`,
   and `os_version=<VERSION_ID>`. A scanner-specific
   `distro=dhi-<release>` qualifier is another representation of that release.
6. Construct the release-scoped OSV ecosystem key:
   `Docker Hardened Images:Alpine:<release>` for APK packages or
   `Docker Hardened Images:Debian:<release>` for Debian packages.
7. Match an OSV affected package with the same exact ecosystem variant and
   package identity.
8. Check whether the installed version exactly equals an entry in
   `affected[].versions`. Independently evaluate every `ECOSYSTEM` range with
   the corresponding APK or dpkg version comparator.
9. Report a finding when either exact-version membership or native range
   inclusion matches. If neither matches, do not report a finding for that
   advisory/package/version.

Canonical feed PURLs and scanner-observed PURLs therefore map to the same
package query identity:

```text
pkg:apk/dhi/coreutils?os_distro=alpine&os_name=dhi&os_version=3.24
pkg:apk/dhi/coreutils@9.11-r0?arch=aarch64&distro=dhi-3.24
  -> Docker Hardened Images:Alpine:3.24
  -> APK comparator

pkg:deb/dhi/coreutils?os_distro=debian&os_name=dhi&os_version=13
pkg:deb/dhi/coreutils@9.7-3%2Bdhi3?arch=arm64&distro=dhi-13
  -> Docker Hardened Images:Debian:13
  -> dpkg comparator
```

The OSV package query identity is versionless. For VEX product matching, use
the same normalized type, namespace, name, lineage, and release, and retain the
exact installed package version:

```text
pkg:apk/dhi/coreutils@9.11-r0?os_distro=alpine&os_name=dhi&os_version=3.24
```

## OSV Examples

`affected[].versions` and `affected[].ranges` have union semantics. Exact
versions remain useful alongside `ECOSYSTEM` ranges because consumers without
the package manager's native comparator can still perform precise equality
matching. For an `under_investigation` assessment, generated DHI OSV uses
`affected[].versions` and omits `affected[].ranges` because the assessment does
not define an affected interval.

APK affected entry:

```json
{
  "package": {
    "ecosystem": "Docker Hardened Images:Alpine:3.24",
    "name": "coreutils",
    "purl": "pkg:apk/dhi/coreutils?os_distro=alpine&os_name=dhi&os_version=3.24"
  },
  "ranges": [{
    "type": "ECOSYSTEM",
    "events": [
      { "introduced": "0" },
      { "fixed": "9.11-r1" }
    ]
  }],
  "versions": ["9.11-r0"]
}
```

Debian affected entry:

```json
{
  "package": {
    "ecosystem": "Docker Hardened Images:Debian:13",
    "name": "coreutils",
    "purl": "pkg:deb/dhi/coreutils?os_distro=debian&os_name=dhi&os_version=13"
  },
  "ranges": [{
    "type": "ECOSYSTEM",
    "events": [
      { "introduced": "0" },
      { "fixed": "9.7-3+dhi4" }
    ]
  }],
  "versions": ["9.7-3+dhi3"]
}
```

Alpine `under_investigation` entry with enumerated versions and no
`affected[].ranges`:

```json
{
  "package": {
    "ecosystem": "Docker Hardened Images:Alpine:3.23",
    "name": "python-3.12",
    "purl": "pkg:apk/dhi/python-3.12?os_distro=alpine&os_name=dhi&os_version=3.23"
  },
  "versions": ["3.12.13-r7"]
}
```

## Proposed public PURL projection (not adopted)

The current upcoming-feed shape reuses an internal advisory owner PURL as the
public OSV package PURL, then inserts an installed version to make each VEX
product PURL. That owner is an exact internal assessment key. Its qualifiers
also carry DHI identity and base release, but they differ from the qualifier
observed in the recorded Syft SBOM. This forces a scanner or importer to
translate between two package PURL shapes before it can match VEX context.

The proposal is to keep the internal HSP owner key unchanged and project a
separate public package identity. For this Alpine example:

| Identity | Current upcoming-feed contract | Proposed public projection |
| --- | --- | --- |
| Internal HSP owner | `pkg:apk/dhi/coreutils?os_distro=alpine&os_name=dhi&os_version=3.24` | Same exact key; no migration of stored assessments. |
| OSV ecosystem | `Docker Hardened Images:Alpine:3.24` | Same release-scoped ecosystem. |
| OSV `affected[].package.purl` | `pkg:apk/dhi/coreutils?os_distro=alpine&os_name=dhi&os_version=3.24` | `pkg:apk/dhi/coreutils?distro=dhi-3.24` |
| VEX `products[].@id` | `pkg:apk/dhi/coreutils@9.11-r0?os_distro=alpine&os_name=dhi&os_version=3.24` | `pkg:apk/dhi/coreutils@9.11-r0?distro=dhi-3.24` |
| Recorded Syft package PURL | `pkg:apk/dhi/coreutils@9.11-r0?arch=aarch64&distro=dhi-3.24` | Same observed package. |

The public fields of one affected OSV entry and its paired VEX statement would
therefore change as follows. Other assessment fields, affected versions, and
native version ranges would keep their current meanings.

Current upcoming-feed `affected[].package`:

```json
{
  "ecosystem": "Docker Hardened Images:Alpine:3.24",
  "name": "coreutils",
  "purl": "pkg:apk/dhi/coreutils?os_distro=alpine&os_name=dhi&os_version=3.24"
}
```

Proposed public `affected[].package`:

```json
{
  "ecosystem": "Docker Hardened Images:Alpine:3.24",
  "name": "coreutils",
  "purl": "pkg:apk/dhi/coreutils?distro=dhi-3.24"
}
```

Current upcoming-feed VEX `products[]` member:

```json
{"@id": "pkg:apk/dhi/coreutils@9.11-r0?os_distro=alpine&os_name=dhi&os_version=3.24"}
```

Proposed public VEX `products[]` member:

```json
{"@id": "pkg:apk/dhi/coreutils@9.11-r0?distro=dhi-3.24"}
```

For Debian 13, the analogous proposed public products would be
`pkg:deb/dhi/coreutils?distro=dhi-13` in OSV and
`pkg:deb/dhi/coreutils@9.7-3%2Bdhi3?distro=dhi-13` in VEX; the internal owner
would keep `os_distro=debian&os_name=dhi&os_version=13`. The `apk`/`deb` type
and `dhi` namespace still identify the package family and producer. The
`distro=dhi-<release>` value carries the base release. Removing every
qualifier would lose that release in a VEX product PURL, where there is no OSV
ecosystem field to recover it from.

This is a candidate public convention based on observed scanner output, not a
claim that `distro` has one universally specified value across scanners. A
PURL-aware consumer may also retain `arch` on its installed-package PURL; the
consumer's matching behavior for that extra qualifier needs verification.
The OSV ecosystem still carries lineage and release because some OSV consumers
match using ecosystem and package name rather than PURL qualifiers.

### Migration and acceptance checks

1. Leave stored owner keys and assessment identity unchanged. Change the
   materializer's public HSP projection and feed renderer together: they
   currently derive public PURLs directly from owner PURLs and validate that
   the owner and public PURL are identical. Keep IMAGE owners on their separate
   contract.
2. Generate candidate OSV/VEX artifacts beside the current feed, then check
   them with Syft, Grype, Trivy, Docker Scout, and the actual feed importers.
   Verify an installed package matches the intended DHI release and version,
   while a different release or version does not. Confirm how each consumer
   handles an extra `arch` qualifier and the release-scoped OSV ecosystem.
3. Update the normative examples, fixtures, and static validator only after
   agreeing on the public shape. Plan a consumer transition before replacing
   public PURLs: exact-PURL consumers may lose matches at cutover. Temporary
   compatibility VEX products are possible to evaluate, but duplicating OSV
   affected entries may produce duplicate findings and needs separate proof.

This proposal concerns the upcoming advisory feed's package owners across DHI
images. It does not replace the separate image-digest and package-subcomponent
shape investigated for image-attached OpenVEX.
