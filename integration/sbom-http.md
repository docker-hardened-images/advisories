<img alt="dhi-banner" src="https://github.com/user-attachments/assets/fc0ca203-3f25-4ae5-aa8e-e3918bbcc31f" />

# Retrieve DHI SBOMs through the public catalog and OCI HTTP APIs

This retrieval procedure is shared by the
[current-production](current-production/README.md) and
[upcoming `ID=dhi`](upcoming-id-dhi/README.md) scanner models. Use the
model-specific guides to interpret package identity and advisory applicability.
For a customer image derived from DHI, first establish the base repository,
platform, and digest using [derived-image base discovery](derived-image-base-discovery.md).

## Purpose

Collect original DHI SBOM attestations without an image-management CLI. Use the
public GitHub catalog to discover repository names, then OCI registry HTTP APIs
to enumerate published tags, resolve platform digests, and download SPDX or
CycloneDX documents.

## Prerequisites

- A Docker Hub account and personal access token (PAT), with access to the images
  being retrieved. Publicly reachable DHI registry endpoints require login;
  restricted variants also require applicable permissions.
- `curl` and `jq` for the registry examples. Git and ripgrep (`rg`) are used for
  the catalog discovery example.
- A repository name in addition to the image digest. A digest alone does not
  identify the registry repository. SBOM lookup uses a platform manifest digest,
  rather than a multiarchitecture index digest.

The GitHub catalog is anonymously readable.

## Steps

### Discover repository names

The [public catalog](https://github.com/docker-hardened-images/catalog) contains
image definitions under `image/`. Read their top-level `image:` values; do not
include package or Helm chart definitions in the image inventory.

```bash
git clone https://github.com/docker-hardened-images/catalog.git
cd catalog
git rev-parse HEAD  # Record the discovery snapshot.
rg --no-filename '^image: dhi\.io/' image --glob '*.yaml' |
  awk '{print $2}' |
  sort -u > repositories.txt
```

For example, `dhi.io/nginx` supplies the repository name `nginx`. Treat definitions
as discovery seeds: registry responses determine which tags and digests are
actually available. Definitions can lead or lag publication. Refresh the catalog
periodically to discover new repositories. This is not a historical digest archive.

See [DHI image definitions](https://docs.docker.com/dhi/how-to/build/) for the
definition format.

### Authenticate to the registry

An unauthenticated request returns a `WWW-Authenticate` bearer challenge. Use its
realm, service, and repository scope to obtain a token. This example uses the
challenge for `dhi.io/nginx`; `curl` prompts for the Docker Hub PAT.

```bash
DOCKER_USER='<Docker Hub username>'
REPO='nginx'

TOKEN=$(
  curl -fsS --user "$DOCKER_USER" --get https://dhi.io/token \
    --data-urlencode 'service=registry.docker.io' \
    --data-urlencode "scope=repository:${REPO}:pull" |
  jq -er '.token // .access_token'
)

registry_get() {
  curl -fsSL \
    -H "Authorization: Bearer $TOKEN" \
    -H 'Accept: application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json' \
    "https://dhi.io/v2/${REPO}/$1"
}
```

Keep credentials and bearer tokens out of logs and saved output. Obtain a new
repository-scoped token when switching repositories, and refresh expired tokens.

### Enumerate tags and resolve platform digests

```bash
registry_get 'tags/list' | jq '.tags'
TAG='1.30-debian13'
registry_get "manifests/${TAG}" > manifest.json
```

For a paginated listing, request `tags/list?n=100`, retain the response headers,
and follow each `Link` with `rel="next"` until no next link remains. Resolve
relative links against `https://dhi.io` and forward credentials only to the
expected registry origin. The `n` parameter controls page size and `last` is the
last tag returned on the preceding page.

For a multiarchitecture index, `.manifests[]` contains per-platform descriptors.
Select actual image platforms, rather than auxiliary attestation descriptors:

```bash
jq '.manifests[] | select(.platform.os == "linux") | {digest, platform}' manifest.json
DIGEST=$(jq -er '.manifests[] |
  select(.platform.os == "linux" and .platform.architecture == "amd64") |
  .digest' manifest.json)
```

If the tag resolves directly to a single image manifest, use its digest from the
`Docker-Content-Digest` response header instead. Deduplicate by repository and
platform digest, retaining all associated tags; multiple tags often point to the
same image. Follow each tag to a digest and then use digest-addressed requests
so a moving tag cannot mix content from different builds within that retrieval.

### Discover and download the SBOM attestation

The HTTP sequence is:

1. `GET /v2/<repo>/referrers/<platform-digest>`.
2. `GET /v2/<repo>/manifests/<attestation-digest>`.
3. `GET /v2/<repo>/blobs/<statement-blob-digest>`.

Select the descriptor using its `in-toto.io/predicate-type` annotation:

- SPDX: `https://spdx.dev/Document`.
- CycloneDX: `https://cyclonedx.org/bom/v1.6`.

This example downloads SPDX and deliberately fails if discovery returns zero or
multiple matching descriptors, rather than silently selecting an arbitrary one:

```bash
ATTESTATION=$(
  registry_get "referrers/${DIGEST}" |
  jq -er '
    [.manifests[] |
      select(.annotations["in-toto.io/predicate-type"] == "https://spdx.dev/Document")]
    | if length == 1 then .[0].digest
      else error("Expected exactly one SPDX attestation") end'
)

BLOB=$(
  registry_get "manifests/${ATTESTATION}" |
  jq -er '
    [.layers[] | select(.mediaType == "application/vnd.in-toto+json")]
    | if length == 1 then .[0].digest
      else error("Expected exactly one in-toto layer") end'
)

registry_get "blobs/${BLOB}" > sbom-statement.json
jq -e '.predicate' sbom-statement.json > sbom.spdx.json
unset TOKEN
```

The blob is an in-toto statement whose `predicate` contains the SBOM. Preserve
the original statement as well as the extracted document. For CycloneDX, select
its predicate type and save the extracted predicate as a CycloneDX document.

See the [OCI Distribution specification](https://github.com/opencontainers/distribution-spec/blob/main/spec.md)
and [Docker's image and attestation access documentation](https://docs.docker.com/dhi/how-to/mirror/).

## Verify

For each retrieval:

- Verify the downloaded manifest and blob SHA-256 hashes against their descriptor
  digests before extracting or reformatting JSON.
- Confirm the statement's `subject[].digest.sha256` matches the requested platform
  digest, and its `predicateType` matches the selected SBOM format.
- Check SPDX's `spdxVersion` or CycloneDX's `bomFormat` and `specVersion`.
- Record repository, tags, platform, image digest, attestation digest, retrieval
  time, and failures separately. An inaccessible image or missing attestation is
  a collection gap, not an empty SBOM.

Content hashing and subject matching do not verify the attestation's signature.
Cryptographic signature verification is a separate operation.

## Troubleshooting

- **401:** follow the bearer challenge, check the Docker credentials, scope, and
  token expiry. A GitHub token is not a Docker registry credential.
- **403 or inaccessible restricted images:** check account permissions and image
  entitlements; do not silently count the image as collected.
- **404 for a catalog tag:** definitions and publication may differ; record the
  missing tag and retry discovery later.
- **Unexpected VEX matching results:** use the image model's integration
  guide to interpret the retrieved inventory. See the
  [current-production FAQ](current-production/docs/faq.md) or the
  [upcoming advisory-routing guide](upcoming-id-dhi/docs/advisory-routing.md).

For background, see
[DHI VEX](https://docs.docker.com/dhi/core-concepts/vex/) and
[scanning DHI images](https://docs.docker.com/dhi/how-to/scan/).
