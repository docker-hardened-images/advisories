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

Generated DHI OSV represents Docker's current advisory state. VEX adds DHI
assessment context, but OSV range generation handles `not_affected` and `fixed`
rather than relying on post-match VEX suppression.

| Assessment state | Generated DHI OSV role | Generated DHI VEX role | Scanner result |
| --- | --- | --- | --- |
| `affected` | Creates a finding by including the DHI package/version range. | Confirms DHI assessment and adds status/action context. | Report finding with DHI context. |
| `under_investigation` | Creates a finding with conservative affected coverage for every applicable DHI package version still under investigation. | Marks the matching DHI product assessment as unresolved and adds status context. | Report the finding even without VEX; when VEX is consumed, show the under-investigation context. |
| `not_affected` | Prevents a finding by excluding the DHI package/version range. | Explains the assessment for exact product matches and remains the published advisory artifact when the advisory is VEX-only. | No finding. |
| `fixed` | Prevents a finding by ending the affected range before the fixed version. | Marks exact DHI product versions as fixed. | No finding for fixed versions. |

`under_investigation` is deliberately fail-closed for vulnerability discovery.
The conservative OSV coverage is scoped to the applicable DHI package,
lineage, and release and remains until Docker resolves the assessment. Resolution
replaces that coverage with the determined `affected` or `fixed` range, or
removes it for `not_affected`. An OSV-only consumer must therefore see the
unresolved package/version as a finding rather than interpreting an omitted
entry as clear.

The `fixed` VEX context is exact product context, not a range. A scanner should
not show a `fixed` statement for `pkg:apk/dhi/foo@1.23` as applying to an image
that contains only `pkg:apk/dhi/foo@1.23.1`. To make `fixed` VEX visible for
`foo@1.23.1`, the generated VEX statement must identify the exact
`foo@1.23.1` product PURL, or scanners can derive fixed-version context from
OSV ranges.

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

For cutover images, generated VEX statements for OS packages should include
concrete DHI package product PURLs:

```json
{
  "vulnerability": {
    "name": "DHI-CVE-2016-2781-coreutils",
    "aliases": ["CVE-2016-2781"]
  },
  "products": [
    {
      "@id": "pkg:apk/dhi/coreutils@9.11-r0?os_distro=alpine&os_name=dhi&os_version=3.24"
    }
  ],
  "status": "affected",
  "action_statement": "Docker has assessed this DHI package version as affected."
}
```

Scanner integrations must construct the VEX product match key from the
normalized DHI package identity defined in
[Package identity and versioning](package-identity-and-versioning.md), retaining
the exact installed package version. Do not substitute an upstream `ID_LIKE`
package PURL or treat a subcomponent PURL as the product match key.

## VEX Is Context, Not The Source Of Discovery

In the upcoming model, DHI OSV records are the vulnerability discovery source
for DHI base-layer OS package PURLs. VEX records carry DHI assessment context
for those advisory/package combinations. Docker always publishes the generated
VEX record, but scanners are not required to consume it to determine whether a
finding exists. In particular, an `under_investigation` result is discoverable
from OSV alone; VEX explains why that result is unresolved.

When a scanner does consume VEX, every generated OSV affected package is
expected to have a matching product in the paired VEX document using that
normalized identity and exact version. A missing document or product match is a
feed integrity error, not a normal no-context path. Continue to report the OSV
finding and surface the integrity error; do not suppress the finding.

Scanners should not need to query upstream Alpine or Debian OSV feeds for a
DHI-owned base-layer package after generated DHI OSV data exists. When scanning
derived images, a DHI package PURL does not by itself prove DHI ownership.
Apply generated DHI OSV/VEX data only when chain-ID/layer attribution places
the package in the DHI base, or when its exact package and version match the
Docker-issued SBOM for a known DHI base image. Otherwise, normalize the package
to its upstream Alpine or Debian identity and use normal upstream advisory
coverage without DHI VEX.
