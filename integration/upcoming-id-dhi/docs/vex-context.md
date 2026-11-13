# VEX Context

[Back to the upcoming `ID=dhi` guide](../README.md)

This page defines VEX behavior for cutover `ID=dhi` images. In the
[current-production model](../../current-production/README.md), VEX may change
or suppress findings produced by upstream advisory matching. In the upcoming
model, generated DHI OSV determines whether a finding exists and generated DHI
VEX supplies additional assessment context.

## OSV And VEX For `ID=dhi`

Every generated DHI advisory that Docker publishes includes a VEX document.
Docker also publishes an OSV document whenever the advisory must produce a
scanner finding; a fully `not_affected` advisory can therefore be VEX-only.
VEX publication is not optional. Scanner consumption of the published VEX
context is.

Generated DHI OSV determines whether a DHI package version is reported as
affected. VEX provides Docker's assessment status and additional context;
scanners do not need VEX to determine whether an OSV entry matches. Under OSV
semantics, a package version is affected if it is listed in
`affected[].versions` or falls within any range in `affected[].ranges`.

| Assessment state | Generated DHI OSV role | Generated DHI VEX role | Scanner result |
| --- | --- | --- | --- |
| `affected` | Creates a finding through native ranges and enumerated affected versions. | Confirms DHI assessment and adds status/action context. | Report finding with DHI context. |
| `under_investigation` | Creates a finding through an open-ended package range (from the earliest known covered version) and known versions. | Marks the matching DHI product assessment as unresolved and adds status context. | Report listed and unlisted package versions even without VEX; when VEX is consumed, show the under-investigation context. |
| `not_affected` | Prevents a finding by omitting positive OSV coverage for the DHI package/version. | Explains the assessment for exact product matches and remains the published advisory artifact when the advisory is VEX-only. | No finding. |
| `fixed` | Prevents a finding by ending the affected range before the fixed version. | Marks exact DHI product versions as fixed. | No finding for fixed versions. |

For vulnerability discovery, scanners treat versions at or above the earliest known covered version of an
`under_investigation` DHI package as conservatively affected within its lineage
and base release. The range has no upper bound, so a
new version matches even before the feed enumerates it. Resolution replaces
this coverage with assessed affected/fixed ranges or removes it for
`not_affected`. VEX remains exact-product context: an unlisted version may
match OSV without a corresponding VEX product statement.

The `fixed` VEX context is exact product context, not a range. A scanner should
not show a `fixed` statement for `pkg:apk/dhi/foo@1.23` as applying to an image
that contains only `pkg:apk/dhi/foo@1.23.1`. To make `fixed` VEX visible for
`foo@1.23.1`, the generated VEX statement must identify the exact
`foo@1.23.1` product PURL, or scanners can derive fixed-version context from
OSV affected versions and ranges.

## Status Semantics

| VEX status | Scanner behavior | User-facing meaning |
| --- | --- | --- |
| `not_affected` | No active finding: generated DHI OSV excludes the package/version. | Docker has assessed that the package/version is not affected in DHI context. |
| `fixed` | No active finding for the fixed package version: generated DHI OSV ends the affected range before that version. | The DHI package has remediated the issue. |
| `affected` | Report the vulnerability and include DHI notes. | Docker has assessed the product as affected. |
| `under_investigation` | Report the vulnerability from the conservative OSV affected coverage; include DHI notes when matching VEX is consumed. | Assessment is not complete or is waiting on upstream/remediation context. |

If generated DHI OSV produces a finding for an exact product whose paired VEX
status is `not_affected` or `fixed`, report a feed-integrity error. Do not use
the VEX status to suppress the contradictory OSV finding.

## VEX Product Identity

For cutover images, generated VEX statements for OS packages name concrete DHI
package product PURLs. A product carries the exact installed version and exactly
one qualifier, `distro=dhi-<release>`:

```json
{
  "vulnerability": {
    "name": "DHI-CVE-2016-2781-coreutils",
    "aliases": ["CVE-2016-2781"]
  },
  "products": [
    {
      "@id": "pkg:apk/dhi/coreutils@9.11-r0?distro=dhi-3.24"
    }
  ],
  "status": "affected",
  "action_statement": "Docker has assessed this DHI package version as affected."
}
```

Match a product against the scanner-observed package PURL with the OpenVEX
subset rule:

- type, namespace, name, and version must be equal;
- every qualifier on the product must be present, with the same value, on the
  scanned PURL;
- extra qualifiers on the scanned PURL, such as `arch` or `upstream`, do not
  prevent a match.

Syft and Grype report packages in `ID=dhi` images as, for example,
`pkg:apk/dhi/coreutils@9.11-r0?arch=aarch64&distro=dhi-3.24`, which matches the
product above. The `distro` qualifier keeps a statement from applying to the
same package version in another DHI release, so do not strip it. Encoding
follows [Package identity and versioning](package-identity-and-versioning.md).

A statement may list more than one product for the same package version.
Match any of them.

Do not substitute an upstream `ID_LIKE` package PURL or treat a subcomponent
PURL as the product match key.

## VEX Is Context, Not The Source Of Discovery

In the upcoming model, DHI OSV records are the vulnerability discovery source
for DHI base-layer OS package PURLs. VEX records carry DHI assessment context
for those advisory/package combinations. Docker always publishes the generated
VEX record, but scanners are not required to consume it to determine whether a
finding exists. In particular, an `under_investigation` result is discoverable
from OSV alone; VEX explains why that result is unresolved.

When a scanner does consume VEX, every generated OSV affected package is
expected to have a matching product in the paired VEX document for the same
package, release, and exact version. A missing document or product match is a
feed integrity error, not a normal no-context path. Continue to report the OSV
finding and surface the integrity error; do not suppress the finding.

Scanners should not need to query upstream Alpine or Debian OSV feeds for a
DHI-owned base-layer package after generated DHI OSV data exists. When scanning
derived images, a DHI package PURL does not by itself prove DHI ownership.
Apply generated DHI OSV/VEX data only when chain-ID/layer attribution places
the package in the DHI base, or when its exact package and version match a
verified Docker-issued base SBOM resolved through the shared
[derived-image base-discovery procedure](../../derived-image-base-discovery.md).
Otherwise, normalize the package to its upstream Alpine or Debian identity and
use normal upstream advisory coverage without DHI VEX.
