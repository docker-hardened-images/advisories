# VEX Context

Generated DHI VEX data gives scanners DHI assessment context to present with
findings produced by DHI or upstream advisory matching.

## OSV And VEX By Model

Current production DHI scanning has two steps: advisory matching creates
candidate findings, then DHI VEX can change or explain the result for Docker's
product context.

| Assessment state | Advisory matching | VEX role | Scanner result |
| --- | --- | --- | --- |
| `affected` | Creates a candidate finding from upstream or DHI advisory data. | Confirms DHI assessment and adds status/action context. | Report finding with DHI context. |
| `under_investigation` | Creates a candidate finding from upstream or DHI advisory data. | Marks DHI assessment as unresolved and adds status context. | Report finding with under-investigation context. |
| `not_affected` | May create a candidate finding from upstream advisory data. | Marks matching DHI product as not affected. | Suppress or annotate finding as not affected. |
| `fixed` | May create a candidate for a vulnerable installed version; advisory range data may identify a fixed version. | Marks only an exactly matching DHI product as fixed. It does not apply to older or different product versions. | Exact fixed product: no active finding. Older vulnerable product: report the finding and show advisory-based upgrade guidance when available. |

In the upcoming `ID=dhi` model, generated DHI OSV already represents Docker's
current advisory state. VEX adds DHI assessment context, but `not_affected` and
`fixed` should normally be handled by OSV range generation rather than
post-match suppression.

| Assessment state | Generated DHI OSV role | Generated DHI VEX role | Scanner result |
| --- | --- | --- | --- |
| `affected` | Creates a finding by including the DHI package/version range. | Confirms DHI assessment and adds status/action context. | Report finding with DHI context. |
| `under_investigation` | Creates a finding by including the DHI package/version range. | Marks DHI assessment as unresolved and adds status context. | Report finding with under-investigation context. |
| `not_affected` | Prevents a finding by excluding the DHI package/version range. | Optional: explains the assessment for exact product matches. | No finding. |
| `fixed` | Prevents a finding by ending the affected range before the fixed version. | Optional: marks exact DHI product versions as fixed. | No finding for fixed versions. |

The optional `fixed` VEX context is exact product context, not a range. A scanner
should not show a `fixed` statement for `pkg:apk/dhi/foo@1.23` as applying to an
image that contains only `pkg:apk/dhi/foo@1.23.1`. To make `fixed` VEX visible
for `foo@1.23.1`, publish a `fixed` VEX statement for the exact `foo@1.23.1`
product PURL, or let scanners derive fixed-version context from OSV ranges.

## Status Semantics

| VEX status | Scanner behavior | User-facing meaning |
| --- | --- | --- |
| `not_affected` | In the upcoming model, should normally have no active finding because OSV excludes the package/version. | Docker has assessed that the package/version is not affected in DHI context. |
| `fixed` | In the upcoming model, should normally have no active finding because OSV ends the affected range before the fixed version. | The DHI package has remediated the issue. |
| `affected` | Report the vulnerability and include DHI notes. | Docker has assessed the product as affected. |
| `under_investigation` | Report the vulnerability and include DHI notes. | Assessment is not complete or is waiting on upstream/remediation context. |

Current production VEX artifacts already contain `not_affected`,
`under_investigation`, and `affected` examples. `fixed` is part of the target
status model even though it was not present in the sampled production corpus.

## Production Examples Used For This Guide

These examples are from the current production advisories repository and are
used as status-shape anchors. Their product PURLs use the current production
model, not the upcoming `pkg:(apk|deb)/dhi/...` OS package model.

| Status | Example |
| --- | --- |
| `not_affected` | Pinned [`aws-privateca-issuer` VEX](https://github.com/docker-hardened-images/advisories/blob/67b6c12a121bc04c225e9c4707912abcc4b022c2/vex/aws-privateca-issuer/dhi-aws-privateca-issuer.vex.json) contains `CVE-2026-6238` for `pkg:deb/debian/glibc-source` with justification `vulnerable_code_cannot_be_controlled_by_adversary`. |
| `under_investigation` | Pinned [`bash` VEX](https://github.com/docker-hardened-images/advisories/blob/67b6c12a121bc04c225e9c4707912abcc4b022c2/vex/bash/dhi-bash.vex.json) contains `CVE-2026-7017` for Debian Perl products, with status notes indicating that Docker is waiting for upstream and Debian analysis or a fix. |
| `affected` | Pinned [`python` VEX](https://github.com/docker-hardened-images/advisories/blob/67b6c12a121bc04c225e9c4707912abcc4b022c2/vex/python/dhi-python.vex.json) contains an `affected` statement for `CVE-2025-12781` and `pkg:dhi/python@3.9.23`, with an action statement explaining why the fix was not ported. |

Observed current-production `not_affected` justifications include:

- `component_not_present`
- `inline_mitigations_already_exist`
- `vulnerable_code_cannot_be_controlled_by_adversary`
- `vulnerable_code_not_in_execute_path`
- `vulnerable_code_not_present`

## Upcoming Package Product Shape

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

Scanner adapters also need to verify whether exact PURL qualifiers matter. The
Grype cutover exploration showed that a VEX statement using the DHI artifact
PURL matched the target finding in Grype's VEX handling, while a statement using
the upstream `ID_LIKE` PURL did not. It also showed that a package listed only
as a subcomponent was not enough for that tested Grype behavior.

## VEX Is Context, Not The Source Of Discovery

In the upcoming model, DHI OSV records are the vulnerability discovery source
for DHI base-layer OS package PURLs. VEX records carry DHI assessment context
for those advisory/package combinations.

Scanners should not need to query upstream Alpine or Debian OSV feeds for a
DHI-owned base-layer package after generated DHI OSV data exists. When scanning
derived images, a DHI package PURL does not by itself prove DHI ownership.
Scanners need product membership, layer attribution, base SBOM membership, or
equivalent provenance before applying generated DHI OSV/VEX data to OS packages
introduced outside the DHI product.
