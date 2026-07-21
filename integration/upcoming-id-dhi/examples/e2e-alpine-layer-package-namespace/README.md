# E2E Alpine Layer Package Namespace Fixture

This fixture demonstrates that scanner-observed OS package PURLs follow the
final image OS identity. The final image is a real DHI Alpine-family base whose
`/etc/os-release` is rewritten to the upcoming `ID=dhi` model. The fixture then
adds Alpine APK package metadata in a later layer.

The `/etc/os-release` rewrite is only a pre-cutover test technique. Production
cutover images will report `ID=dhi` without scanner-side or customer-side
mutation. The later-layer `jq` addition is separate and exists to exercise
per-package product-membership routing in a derived image.

Both source manifests are pinned for `linux/arm64`:

```text
dhi.io/bash:5-alpine3.24@sha256:e2b67997780c37dc8352fb3e1bae077497216767cd5edb25c710e3a0fef232ec
alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b
```

Syft `1.46.0` observed the later-layer package as
`pkg:apk/dhi/jq@1.8.1-r0?arch=aarch64&distro=dhi-3.24`, even though its package
metadata came from Alpine. That proves the DHI package namespace is not enough,
by itself, to establish DHI product membership or advisory coverage.

## Package Membership Trace

The pinned DHI base SBOM contains `coreutils@9.11-r0` but not `jq@1.8.1-r0`.
In the recorded scanner-backed observation, the derived SBOM contains 44 APK
packages instead of the base's 43; `jq` is the only addition.

| Package | Scanner PURL | Membership evidence | Advisory routing |
| --- | --- | --- | --- |
| `coreutils@9.11-r0` | `pkg:apk/dhi/coreutils@9.11-r0?...` | Present in the pinned DHI base SBOM. | Apply generated DHI OSV and matching VEX context. |
| `jq@1.8.1-r0` | `pkg:apk/dhi/jq@1.8.1-r0?...` | Absent from the DHI base SBOM and added by the derived image. | Do not apply generated DHI OSV without separate DHI provenance. |

Syft discovers both package records through the final
`/lib/apk/db/installed`, so both package artifacts point at the final metadata
layer. That location alone does not establish ownership. Syft's package-file
relationships retain more specific layer evidence: `/bin/coreutils` remains in
the DHI base package layer, while `/usr/bin/jq` comes from a later copy layer.
The fixture uses pinned base-SBOM membership as the primary routing evidence;
the file-layer trace explains and corroborates the result.

The derived image's first five recorded layer digests exactly match the
simulated DHI base snapshot. The remaining layers stage `jq` package metadata,
copy the `jq` binary, and update the final APK catalog. The compact SBOM records
those layers in order with factual roles derived from image history, and every
package evidence reference resolves to one of them.

In production, the base SBOM or equivalent membership data must come from a
trusted DHI artifact or attestation. A scanner must not trust an arbitrary SBOM
supplied with a derived image as proof of DHI product membership.

"Later layer" is not a universal exclusion rule. A later package with trusted
DHI provenance could still be covered. This fixture excludes `jq` because it
has no such evidence, not merely because it was added later.

## Files

| File | Purpose |
| --- | --- |
| `Dockerfile` | Builds a local image from a DHI Alpine base and adds later-layer APK package metadata. |
| `sbom.json` | Compact derived-image snapshot with the base-layer prefix, added layers, and package catalog/file evidence. |
| `expected.json` | Per-package routing: DHI OSV applies to inherited `coreutils`, but not to `jq` without separate DHI provenance. |
