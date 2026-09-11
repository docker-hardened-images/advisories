<img alt="dhi-banner" src="https://github.com/user-attachments/assets/fc0ca203-3f25-4ae5-aa8e-e3918bbcc31f" />

# DHI Derived-Image Base Discovery

This document defines how a scanner can recover and verify the Docker Hardened
Images (DHI) base of an OCI-derived customer image. The procedure is shared by
the [current-production](current-production/README.md) and
[upcoming `ID=dhi`](upcoming-id-dhi/README.md) scanner models. The models use
the resulting package-origin evidence differently, but base discovery is the
same.

This procedure applies to images built `FROM` a DHI image. It does not infer an
OCI parent for a DHI customization assembled independently from shared build
instructions.

## Boundary And Base Digest Are Different

A derived image can inherit the `com.docker.dhi.chain-id` label. A scanner can
recompute cumulative ChainIDs from the final image config's ordered
`rootfs.diff_ids` and locate the matching DHI base-layer boundary.

The ChainID is not an OCI manifest digest, an image reference, or an OCI
referrer lookup key. It cannot by itself identify the repository and
platform-manifest digest needed to retrieve the base image's Docker-issued
SBOM.

Standard OCI image manifests, configs, and history do not provide a parent
image lookup. Do not construct a mutable tag from inherited DHI name or version
labels and assume it identifies the base that was used.

OCI referrers are associated with a specific subject digest. Building a new
derived image does not reattach the DHI base image's SBOM to the derived image
digest. The scanner must recover and verify the base platform-manifest digest
before it can retrieve that base's Docker-issued SBOM.

## Deterministic Provenance Path

When the customer image publishes BuildKit/SLSA provenance containing resolved
dependencies, use the following procedure:

1. Resolve the customer image to the platform manifest being scanned and
   retrieve its associated SLSA provenance. Depending on how the image was
   published, the provenance can be represented as an OCI referrer or an
   attestation manifest in the image index.
2. Inspect `predicate.buildDefinition.resolvedDependencies` for DHI OCI image
   candidates. A BuildKit dependency URI can include the repository from which
   the base was pulled, its index digest, and the platform. The repository can
   be `dhi.io` or a customer mirror.
3. If the dependency digest identifies an image index, resolve the recorded
   platform to its child platform-manifest digest.
4. Fetch the candidate DHI platform manifest and config. If the dependency came
   from a mirror, require the mirror to preserve the manifest and Docker-issued
   attestations, or resolve the digest to its canonical DHI repository through
   other trusted metadata.
5. Verify that the candidate base config's complete `rootfs.diff_ids` list is
   an exact prefix of the derived image's `rootfs.diff_ids` list.
6. Compute the ChainID of that prefix and require it to equal the derived
   image's `com.docker.dhi.chain-id` value.
7. List OCI referrers for the verified DHI platform-manifest digest and select
   its Docker-issued SPDX or CycloneDX SBOM.
8. Use the SBOM together with layer attribution to determine whether each
   package was inherited unchanged, added, replaced, or modified later.

Treat the provenance dependency as a candidate until the rootfs-prefix and
ChainID checks pass. Provenance can contain dependencies from multiple build
stages; do not select a candidate merely because its URI uses `dhi.io` or its
config carries DHI labels. A digest identifies content, but an OCI Distribution
API lookup still requires a repository from which the scanner can retrieve the
manifest and Docker-issued SBOM.

## When Provenance Is Unavailable

Without resolved base provenance, a supplied base reference, or an
authoritative external mapping, a scanner cannot recover the base manifest
digest from the derived image. The ChainID can locate the claimed boundary,
but no OCI registry operation resolves a ChainID back to a manifest.

Valid alternatives are:

- receive the exact DHI base reference and platform from the caller or build
  system, then perform the prefix and ChainID verification above;
- use other trusted build provenance that records the DHI base repository,
  digest, and platform; or
- use a Docker-published mapping from DHI ChainID and platform to canonical
  base manifests, if such a service or feed becomes available.

If DHI package origin cannot be established, fail safely:

| Scanner model | Behavior |
| --- | --- |
| Current production | Do not apply DHI VEX to suppress a finding whose DHI base origin is unproven. |
| Upcoming `ID=dhi` | Do not select generated DHI advisory data from the package namespace alone; use the upstream routing defined by the upcoming guide. |

## Verified Example

The upcoming guide's
[Alpine derived-image fixture](upcoming-id-dhi/examples/e2e-alpine-layer-package-namespace/README.md)
was built for `linux/arm64` with BuildKit `--provenance=mode=max` from this
pinned production base:

```text
dhi.io/bash:5-alpine3.24@sha256:e2b67997780c37dc8352fb3e1bae077497216767cd5edb25c710e3a0fef232ec
```

The standard derived-image manifest and config inherited this ChainID:

```text
sha256:a67bcf0f9ddb1dbfde823a9b843e2c59d4428b928e877a95c4750b2ca520c1aa
```

They did not contain the base index or platform-manifest digest. The separate
SLSA provenance included the base repository, index digest, and platform:

```text
pkg:docker/dhi.io/bash@5-alpine3.24?digest=sha256:e2b679...&platform=linux%2Farm64
```

```text
base index digest:      sha256:e2b67997780c37dc8352fb3e1bae077497216767cd5edb25c710e3a0fef232ec
arm64 platform digest:  sha256:c5295aa6c4a01bef0e09e18849089e318d8232ca66ec7ded104baea243dde387
```

Resolving the index selected the `arm64` platform manifest. Its four
`rootfs.diff_ids` exactly matched the first four entries in the derived image,
and their ChainID matched the inherited label. OCI referrer discovery on that
platform manifest returned the Docker-issued CycloneDX SBOM artifact:

```text
sha256:b5090997dfad89f60517e59c2ae121543d41a7a26801b640d7d1bd5a3b49f590
```

This demonstrates both sides of the contract: provenance can supply the base
digest, while the rootfs prefix and ChainID verify that the derived image
actually contains that DHI base.
