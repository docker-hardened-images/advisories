# Package Identity and Versioning

The `ID=dhi` cutover changes how DHI operating-system packages are namespaced.
It does not replace the package manager's version grammar or ordering.

This document defines the target package identity and version contract for
generated DHI OSV records and scanner integrations. The contract applies after
an image has cut over to `/etc/os-release` `ID=dhi`.

## Contract

| Base lineage and release | OSV ecosystem | OSV package PURL | Installed package PURL | Version comparison |
| --- | --- | --- | --- | --- |
| Alpine 3.24 | `Docker Hardened Images:Alpine:3.24` | `pkg:apk/dhi/<name>?os_distro=alpine&os_name=dhi&os_version=3.24` | `pkg:apk/dhi/<name>@<version>?...` | APK |
| Debian 13 | `Docker Hardened Images:Debian:13` | `pkg:deb/dhi/<name>?os_distro=debian&os_name=dhi&os_version=13` | `pkg:deb/dhi/<name>@<version>?...` | Debian/dpkg |

Generated DHI OSV records use `ECOSYSTEM` ranges for both package families.
The ecosystem suffix has two roles:

- `Alpine` or `Debian` selects the package lineage and native comparator;
- the final segment, such as `3.24` or `13`, partitions matching by base
  release.

The package format is not a sufficient ecosystem partition. `apk` does not
inherently mean Alpine, and `deb` does not inherently mean Debian. Future DHI
bases could share a package format while requiring different package lineage
or vulnerability treatment. More immediately, two Alpine or Debian releases
can contain the same package name and version while requiring different
advisory treatment.

`Docker Hardened Images` without a suffix identifies the registered feed
family and OSV datasource filter. It is not a package ecosystem to use in an
OSV affected entry or package query. Lineage-only variants such as
`Docker Hardened Images:Alpine` are also incomplete. `pkg:dhi/...` is not a
package identity in the upcoming model.

## Image And Package Identity

Cutover images report:

```text
ID=dhi
ID_LIKE=alpine   # or debian
VERSION_ID=<underlying distribution version>
```

`ID=dhi` identifies the image as DHI. `ID_LIKE` and `VERSION_ID` describe the
base lineage and release. The canonical package PURL carries the same values in
`os_distro` and `os_version`; those qualifiers, together with the PURL type,
are the authoritative input for deriving the OSV ecosystem variant.

The OSV affected package PURL omits `@version`. Concrete installed versions
come from the package database or SBOM and appear in the scanner's versioned
PURL. OSV range events and, when available, `affected[].versions` carry the
version data used to decide whether that installed package is affected.

A DHI PURL is package identity, not proof of product membership. Derived-image
integrations still need DHI base-SBOM membership, layer attribution,
provenance, or equivalent evidence before applying generated DHI advisory data.

## Native Version Semantics

### APK

DHI APK packages retain APK versions and revisions. For example, current DHI
`coreutils` package definitions build version `9.11` with package revision
`r0`, producing installed version `9.11-r0`. A later DHI package rebuild can
produce `9.11-r1` without changing the upstream release.

APK ordering must determine that:

```text
9.11-r0 < 9.11-r1
```

Implementations must also preserve APK's native handling of pre-release
markers and package revisions. These versions must not be interpreted as
SemVer.

### Debian

DHI Debian packages retain Debian versions. For example, current DHI
`coreutils` definitions build Debian version `9.7-3` with DHI revision `3`,
producing installed version `9.7-3+dhi3`.

Debian ordering must handle the complete `[epoch:]upstream-version[-revision]`
shape, including `~`, Debian revisions, and DHI rebuild suffixes. For example:

```text
9.7-3 < 9.7-3+dhi1 < 9.7-3+dhi3
```

## Matching Process

For each scanner-observed OS package:

1. Establish that the package belongs to the DHI product being assessed.
2. Parse the PURL and require namespace `dhi`.
3. Normalize scanner qualifier `distro=dhi-<release>` to the canonical
   `os_name=dhi` and `os_version=<release>` values.
4. Require `apk` with `os_distro=alpine`, or `deb` with
   `os_distro=debian`.
5. Derive `Docker Hardened Images:Alpine:<release>` or
   `Docker Hardened Images:Debian:<release>`.
6. Match an OSV affected package with the same exact ecosystem variant and
   package identity.
7. Evaluate its `ECOSYSTEM` range with the corresponding APK or dpkg version
   comparator.
8. Report a finding only when the installed version falls inside the affected
   range.

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

If canonical and scanner qualifier forms are both present, they must agree.
Missing release context or conflicting type, lineage, or release values is a
contract error.

Do not retry a failed native parse with SemVer or lexical string comparison.
An unsupported family, ecosystem/PURL mismatch, or invalid native version is a
contract error and must be surfaced rather than interpreted as unaffected.

## OSV Examples

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

## Producer And Consumer Requirements

Feed producers must derive the public ecosystem variant from the canonical
package PURL, validate that any stored package-family hint agrees with its type
and lineage, require release context, validate native versions and ranges, and
serialize affected entries deterministically.

Consumers must preserve the PURL type and namespace, query by the exact
ecosystem variant or canonical PURL, and use the native comparator selected by
that identity. They must not discard release context while constructing package
query identity. The unsuffixed feed-family name must not fan out implicitly to
all package lineages or releases during a package query.
