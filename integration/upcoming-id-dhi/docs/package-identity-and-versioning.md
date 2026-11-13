# Package Identity and Versioning

The `ID=dhi` cutover changes how DHI operating-system packages are namespaced.
It does not replace the package manager's version grammar or ordering.

This document defines the target package identity and version contract for
generated DHI OSV records and scanner integrations. The contract applies after
an image has cut over to `/etc/os-release` `ID=dhi`.

## Contract

| Base lineage and release | OSV ecosystem | OSV package PURL | VEX product PURL | Installed package PURL | Version comparison |
| --- | --- | --- | --- | --- | --- |
| Alpine 3.24 | `Docker Hardened Images:Alpine:3.24` | `pkg:apk/dhi/<name>` | `pkg:apk/dhi/<name>@<version>?distro=dhi-3.24` | `pkg:apk/dhi/<name>@<version>?...` | APK |
| Debian 13 | `Docker Hardened Images:Debian:13` | `pkg:deb/dhi/<name>` | `pkg:deb/dhi/<name>@<version>?distro=dhi-13` | `pkg:deb/dhi/<name>@<version>?...` | Debian/dpkg |

Identity rules:

- **The OSV package PURL is versionless and carries no qualifiers.** The
  release appears only in the ecosystem, so route OSV matching by ecosystem.
- **The release is the image's `VERSION_ID`:** the Alpine major and minor
  version, such as `3.24`, or the Debian major version, such as `13`. It never
  carries a point release.
- **A VEX product carries exactly one qualifier, `distro=dhi-<release>`.** This
  is the form Syft and Grype report for packages in `ID=dhi` images; see
  [VEX context](vex-context.md#vex-product-identity) for matching.
- **Encoding.** PURLs follow the PURL specification's percent-encoding: `+`
  is encoded as `%2B`, while `:` and `~` stay raw. For example, Debian version
  `1:1.3.dfsg+really1.3.1-1+dhi1` appears as
  `@1:1.3.dfsg%2Breally1.3.1-1%2Bdhi1`. The OSV `name`, `versions`, and range
  events carry the raw values.
- **The package name is the installed binary package name** the package manager
  reports, such as `libc6`, not its source package.
- **No generated DHI record carries `os_*` qualifiers.** A consumer that
  encounters one must check that it agrees with the ecosystem and reject the
  entry if it does not.
- **`arch` is reserved.** No current record carries it. A future OSV entry may
  carry an `arch` qualifier to narrow it to one architecture, so consumers must
  not reject an entry because of it.

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
base lineage and release. Together with the package PURL type, they select the
release-scoped OSV ecosystem and native version comparator. Syft and Grype
already report the release on each package as `distro=dhi-<VERSION_ID>`.

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
5. Construct the release-scoped OSV ecosystem key:
   `Docker Hardened Images:Alpine:<release>` for APK packages or
   `Docker Hardened Images:Debian:<release>` for Debian packages.
6. Match an OSV affected package whose ecosystem equals that key and whose PURL
   has the same type, namespace, and name. Feed PURLs carry no qualifiers, so
   compare without the scanner's qualifiers.
7. Check whether the installed version exactly equals an entry in
   `affected[].versions`. Independently evaluate every `ECOSYSTEM` range with
   the corresponding APK or dpkg version comparator.
8. Report a finding when either exact-version membership or native range
   inclusion matches. If neither matches, do not report a finding for that
   advisory/package/version.

Feed PURLs and scanner-observed PURLs therefore reach the same OSV entry:

```text
feed:    pkg:apk/dhi/coreutils in Docker Hardened Images:Alpine:3.24
scanner: pkg:apk/dhi/coreutils@9.11-r0?arch=aarch64&distro=dhi-3.24
  -> Docker Hardened Images:Alpine:3.24
  -> APK comparator

feed:    pkg:deb/dhi/coreutils in Docker Hardened Images:Debian:13
scanner: pkg:deb/dhi/coreutils@9.7-3%2Bdhi3?arch=arm64&distro=dhi-13
  -> Docker Hardened Images:Debian:13
  -> dpkg comparator
```

The OSV package query identity is versionless. A VEX product names the exact
installed version and the release, and matches the scanner's PURL by the
OpenVEX subset rule described in [VEX context](vex-context.md#vex-product-identity):

```text
pkg:apk/dhi/coreutils@9.11-r0?distro=dhi-3.24
```

## OSV Examples

`affected[].versions` and `affected[].ranges` have union semantics. Exact
versions remain useful alongside `ECOSYSTEM` ranges because consumers without
the package manager's native comparator can still perform precise equality
matching. For an `under_investigation` package assessment, generated DHI OSV
retains known versions and adds an open-ended `ECOSYSTEM` range from
the earliest known covered version. Unlisted versions at or above that boundary also match within the same package,
lineage, and base release; no fixed boundary is claimed.

APK affected entry:

```json
{
  "package": {
    "ecosystem": "Docker Hardened Images:Alpine:3.24",
    "name": "coreutils",
    "purl": "pkg:apk/dhi/coreutils"
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
    "purl": "pkg:deb/dhi/coreutils"
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

Alpine `under_investigation` entry with known versions and an open-ended range
covering versions from the earliest known covered version within its lineage and base release:

```json
{
  "package": {
    "ecosystem": "Docker Hardened Images:Alpine:3.23",
    "name": "python-3.12",
    "purl": "pkg:apk/dhi/python-3.12"
  },
  "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "3.12.13-r7"}]}],
  "versions": ["3.12.13-r7"]
}
```

For under-investigation packages, select the earliest known covered version
using native APK/dpkg ordering, including epochs and revisions. This is a
coverage boundary derived from the current snapshot, not proof of when the
vulnerability was introduced or that earlier releases are safe. Earlier
unlisted versions do not match this entry. A backfilled earlier covered version
moves the lower bound on regeneration; future versions remain covered without
waiting for enumeration. Comparator-equivalent spellings use a deterministic
lexical tie-break. Versions rejected by the native parser fail publication rather than silently
falling back to `0` or inventing a boundary.
