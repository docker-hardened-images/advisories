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

The recorded scanner snapshot for the pinned DHI base contains
`coreutils@9.11-r0` but not `jq@1.8.1-r0`. It stands in for a known base's
Docker-issued membership SBOM during local validation; the fixture does not
retrieve an OCI referrer or verify its attachment to a platform-manifest
digest. In the recorded scanner-backed observation, the derived SBOM contains
44 APK packages instead of the base's 43; `jq` is the only addition.

| Package | Scanner PURL | Membership evidence | Advisory routing |
| --- | --- | --- | --- |
| `coreutils@9.11-r0` | `pkg:apk/dhi/coreutils@9.11-r0?...` | Present in the recorded base snapshot, with package-file evidence in the base-layer prefix. | Apply generated DHI OSV and matching VEX context. |
| `jq@1.8.1-r0` | `pkg:apk/dhi/jq@1.8.1-r0?...` | Absent from the recorded base snapshot, with package-file evidence in later layers. | Normalize to `pkg:apk/alpine/jq@1.8.1-r0?...` and use normal upstream Alpine coverage. |

Syft discovers both package records through the final
`/lib/apk/db/installed`, so both package artifacts point at the final metadata
layer. That location alone does not establish ownership. Syft's package-file
relationships retain more specific layer evidence: `/bin/coreutils` remains in
the DHI base package layer, while `/usr/bin/jq` comes from a later copy layer.
The fixture exercises both exact package-and-version comparison with a recorded
base snapshot and package layer attribution. It uses the pinned base-layer
prefix in place of processing a `com.docker.dhi.chain-id` label.

The derived image's first five recorded layer digests exactly match the
simulated DHI base snapshot. The remaining layers stage `jq` package metadata,
copy the `jq` binary, and update the final APK catalog. The compact SBOM records
those layers in order with factual roles derived from image history, and every
package evidence reference resolves to one of them.

In production, a scanner can establish DHI package origin by resolving the
`com.docker.dhi.chain-id` boundary and attributing packages to DHI base layers.
If the exact base image is already known, the scanner can instead compare
against the Docker-issued SPDX or CycloneDX SBOM attached to that base's
resolved platform-manifest digest. A scanner must not treat an arbitrary SBOM
supplied with the derived image as a Docker-issued base SBOM.

This fixture excludes `jq` because it is absent from the recorded base snapshot
and its package-file evidence is in later layers. Both observations classify it
as customer-added. Its DHI namespace is scanner-observed identity only; advisory
routing uses the corresponding upstream Alpine identity and coverage.

## Files

| File | Purpose |
| --- | --- |
| `Dockerfile` | Builds a local image from a DHI Alpine base and adds later-layer APK package metadata. |
| `sbom.json` | Compact derived-image snapshot with the base-layer prefix, added layers, and package catalog/file evidence. |
| `expected.json` | Per-package routing: DHI OSV applies to base-attributed `coreutils`, but not to customer-added `jq`. |
