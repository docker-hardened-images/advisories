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
   the Docker-issued SBOM for a known DHI base image. If membership is not
   established, normalize the package to the upstream family and release from
   `ID_LIKE` and `VERSION_ID`, use normal upstream advisory coverage with native
   APK or dpkg version semantics, and stop this DHI matching process.
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
