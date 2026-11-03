<img alt="dhi-banner" src="https://github.com/user-attachments/assets/fc0ca203-3f25-4ae5-aa8e-e3918bbcc31f" />

# Retrieve DHI SBOMs through the public catalog and OCI HTTP APIs

This procedure is shared by the [current-production](current-production/README.md)
and [upcoming `ID=dhi`](upcoming-id-dhi/README.md) scanner models. Use those guides
for package identity and advisory applicability. For a derived customer image,
first establish the base repository, platform, and digest using
[derived-image base discovery](derived-image-base-discovery.md).

## Prerequisites

The examples use Bash, Git, curl, jq, standard text utilities, and `sha256sum`
(on macOS, install GNU coreutils or substitute `shasum -a 256`). They require no
image-management CLI. Run the Bash blocks below in order in the same shell.

The GitHub catalog is anonymously readable. Registry requests require a Docker
Hub account and PAT with access to the images being retrieved; restricted
variants also require applicable permissions.

Digest lookup also needs the repository name: a digest alone does not locate a
registry repository. Use a platform manifest digest for SBOM discovery; resolve
a multiarchitecture index to its platform descriptors first.

## Discover repositories

Use the [public catalog](https://github.com/docker-hardened-images/catalog)'s
image definitions as discovery seeds. Strip `dhi.io/` so each line can be used
directly as `REPO`, for example `nginx`:

```bash
set -euo pipefail

git clone --depth 1 https://github.com/docker-hardened-images/catalog.git catalog
git -C catalog rev-parse HEAD  # Record the discovery snapshot.
grep -rh --include='*.yaml' '^image: dhi\.io/' catalog/image |
  sed 's#^image: dhi\.io/##' | sort -u > repositories.txt

OUT='./dhi-sboms'
mkdir -p "$OUT"
```

Registry responses determine which tags and digests are available; definitions
can lead or lag publication. Refresh discovery periodically. This procedure
collects currently discoverable images accessible to the account, not a complete
historical digest archive. See [DHI image definitions](https://docs.docker.com/dhi/how-to/build/).

## Configure authentication and HTTP helpers

For an interactive session, set `DOCKER_USER` to your Docker Hub username and
leave `DOCKER_NETRC` unset. Curl prompts for the PAT each time a token is minted.

For unattended collection, set `DOCKER_NETRC` to an existing protected netrc file
provided by your credential store. Its entry has this format:

```text
machine dhi.io
login <Docker Hub username>
password <Docker Hub PAT>
```

Restrict that file to its owner (`chmod 600`), exclude it from source control,
and do not enable shell tracing or log credentials. A GitHub token is not a
Docker registry credential. For example, set
`DOCKER_NETRC="$HOME/.config/dhi/netrc"` before the following block.

An unauthenticated registry request returns a `WWW-Authenticate` bearer challenge.
The helper uses the observed `dhi.io` realm and service; use the challenge's
values if integrating with another registry. Tokens are scoped per repository.
The helper uses `expires_in` to renew early and retries one 401 with a fresh token.

```bash
REGISTRY='https://dhi.io'
if [[ -n "${DOCKER_NETRC:-}" ]]; then
  AUTH=(--netrc-file "$DOCKER_NETRC")
else
  : "${DOCKER_USER:?Set DOCKER_USER or DOCKER_NETRC}"
  AUTH=(--user "$DOCKER_USER")
fi
TOKEN=''
TOKEN_REPO=''
TOKEN_UNTIL=0

mint_token() {
  local reply lifetime
  reply=$(curl -fsS "${AUTH[@]}" --get "$REGISTRY/token" \
    --data-urlencode 'service=registry.docker.io' \
    --data-urlencode "scope=repository:${REPO}:pull") || return 1
  TOKEN=$(jq -er '.token // .access_token | select(type == "string" and length > 0)' <<< "$reply") || return 1
  lifetime=$(jq -er '(.expires_in // 60) | select(type == "number" and . > 0) | floor' <<< "$reply") || return 1
  TOKEN_REPO=$REPO
  TOKEN_UNTIL=$(( $(date +%s) + lifetime - 15 ))
}

# Save the raw response body and headers. Call directly, not in $(...), so token
# renewal persists in this shell. Only curl's HTTP status is captured internally.
registry_get() {
  local path=$1 body=$2 headers=$3 url status attempt
  case "$path" in
    "$REGISTRY/v2/$REPO/"*) url=$path ;;
    "/v2/$REPO/"*) url="$REGISTRY$path" ;;
    tags/list*|manifests/*|referrers/*|blobs/*) url="$REGISTRY/v2/$REPO/$path" ;;
    *) printf 'Refusing an unexpected registry URL\n' >&2; return 1 ;;
  esac
  for attempt in 1 2; do
    if [[ -z "$TOKEN" || "$TOKEN_REPO" != "$REPO" || $(date +%s) -ge $TOKEN_UNTIL ]]; then
      mint_token || return 1
    fi
    # Supplying the bearer through stdin keeps it out of curl's command line.
    if ! status=$(printf 'header = "Authorization: Bearer %s"\n' "$TOKEN" |
      curl --config - -sS -L --proto '=https' --proto-redir '=https' \
        -H 'Accept: application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json' \
        -D "$headers.part" -o "$body.part" -w '%{http_code}' "$url"); then
      rm -f "$body.part" "$headers.part"
      return 1
    fi
    if [[ "$status" == 200 ]]; then
      mv "$body.part" "$body" || return 1
      mv "$headers.part" "$headers" || return 1
      return 0
    fi
    rm -f "$body.part" "$headers.part"
    if [[ "$status" == 401 && "$attempt" == 1 ]]; then
      TOKEN=''
    else
      printf 'Registry HTTP %s for %s\n' "$status" "$path" >&2
      return 1
    fi
  done
}

list_tags() {
  local destination=$1 next='tags/list?n=100' link
  : > "$destination" || return 1
  while [[ -n "$next" ]]; do
    registry_get "$next" "$OUT/$REPO/tag-page.json" "$OUT/$REPO/tag-page.headers" || return 1
    jq -er '.tags[]' "$OUT/$REPO/tag-page.json" >> "$destination" || return 1
    # Header names are case-insensitive; dhi.io returns a relative /v2/... link.
    link=$(awk 'tolower($1) == "link:" {sub(/\r$/, ""); print}' "$OUT/$REPO/tag-page.headers")
    next=$(printf '%s\n' "$link" | sed -n 's/.*<\([^>]*\)>;[[:space:]]*rel="next".*/\1/p')
  done
}
```

Curl follows blob redirects without forwarding Authorization to another origin;
do not add `--location-trusted`. Pagination links are restricted to the same
registry and repository by `registry_get`. The helper fails after a second 401
or another unsuccessful response instead of treating it as an empty result.

## Verify and download original SBOMs

The lookup sequence is platform digest → referrers → attestation manifest →
in-toto statement blob. Select descriptors by `in-toto.io/predicate-type`:

- SPDX: `https://spdx.dev/Document`.
- CycloneDX: `https://cyclonedx.org/bom/v1.6`.

Referrers can also include `https://scout.docker.com/sbom/v0.1`. This is Scout's
own format; it is not an SPDX or CycloneDX attestation and is excluded below.

Save manifests and blobs as raw bytes before checking their digests. Piping a
manifest through jq before saving it changes those bytes. The following helpers
verify SHA-256 and require a nonempty subject list in which **every** subject
matches the requested platform digest. Repeated identical subjects are valid.

```bash
verify_sha256() {
  local expected=$1 file=$2
  [[ "$expected" =~ ^sha256:[0-9a-f]{64}$ ]] || return 1
  printf '%s  %s\n' "${expected#sha256:}" "$file" | sha256sum -c - > /dev/null
}

fetch_sboms() {
  local digest=$1 directory=$2 format predicate attestation blob
  mkdir -p "$directory" || return 1
  registry_get "manifests/$digest" "$directory/image.json" "$directory/image.headers" || return 1
  verify_sha256 "$digest" "$directory/image.json" || return 1
  registry_get "referrers/$digest" "$directory/referrers.json" "$directory/referrers.headers" || return 1
  for format in spdx cyclonedx; do
    case "$format" in
      spdx) predicate='https://spdx.dev/Document' ;;
      cyclonedx) predicate='https://cyclonedx.org/bom/v1.6' ;;
    esac
    attestation=$(jq -er --arg p "$predicate" '
      [.manifests[] | select(.annotations["in-toto.io/predicate-type"] == $p)]
      | if length == 1 then .[0].digest else error("Expected one matching SBOM") end
    ' "$directory/referrers.json") || return 1
    registry_get "manifests/$attestation" "$directory/$format-manifest.json" "$directory/$format-manifest.headers" || return 1
    verify_sha256 "$attestation" "$directory/$format-manifest.json" || return 1
    blob=$(jq -er '
      [.layers[] | select(.mediaType == "application/vnd.in-toto+json")]
      | if length == 1 then .[0].digest else error("Expected one in-toto layer") end
    ' "$directory/$format-manifest.json") || return 1
    registry_get "blobs/$blob" "$directory/$format-statement.json" "$directory/$format-statement.headers" || return 1
    verify_sha256 "$blob" "$directory/$format-statement.json" || return 1
    jq -e --arg d "${digest#sha256:}" --arg p "$predicate" '
      .predicateType == $p and
      (.subject | type == "array" and length > 0 and all(.[]; .digest.sha256 == $d))
    ' "$directory/$format-statement.json" > /dev/null || return 1
    jq -e '.predicate' "$directory/$format-statement.json" > "$directory/$format.json" || return 1
  done
}

collect_tag() {
  local tag=$1 directory="$OUT/$REPO" digest tag_digest
  mkdir -p "$directory/tags" || return 1
  registry_get "manifests/$tag" "$directory/tags/$tag.json" "$directory/tags/$tag.headers" || return 1
  # The response bytes establish the tag's digest; check the header when supplied.
  tag_digest=$(awk 'tolower($1) == "docker-content-digest:" {gsub(/\r/, ""); print $2}' "$directory/tags/$tag.headers")
  if [[ -n "$tag_digest" ]]; then
    verify_sha256 "$tag_digest" "$directory/tags/$tag.json" || return 1
  else
    tag_digest="sha256:$(sha256sum "$directory/tags/$tag.json" | awk '{print $1}')"
  fi
  printf '%s\t%s\n' "$tag" "$tag_digest" >> "$directory/tag-digests.tsv" || return 1
  if jq -e '.manifests | type == "array"' "$directory/tags/$tag.json" > /dev/null; then
    jq -er '.manifests[] | select(.platform.os == "linux") | .digest' \
      "$directory/tags/$tag.json" > "$directory/platform-digests.txt" || return 1
  else
    printf '%s\n' "$tag_digest" > "$directory/platform-digests.txt" || return 1
  fi
  while IFS= read -r digest; do
    # A marker is written only after both formats have been downloaded/verified.
    if [[ ! -f "$directory/$digest/complete" ]]; then
      fetch_sboms "$digest" "$directory/$digest" || return 1
      touch "$directory/$digest/complete" || return 1
    fi
  done < "$directory/platform-digests.txt"
}
```

Each directory retains the raw image/attestation manifests, original statements,
and extracted documents. Tag manifests preserve platform descriptors;
`tag-digests.tsv` preserves tag aliases. The completion marker deduplicates by
repository and platform digest. Use a fresh output directory for a fresh
attestation snapshot; reusing it skips previously completed image digests.
Content hashes and subject matching do not verify cryptographic signatures.

## Retrieve one image or loop over the catalog

To start with one repository, list its current tags and choose one from that
output instead of copying a version that may become stale:

```bash
REPO='nginx'
mkdir -p "$OUT/$REPO"
list_tags "$OUT/$REPO/tags.txt"
cat "$OUT/$REPO/tags.txt"
read -r -p 'Tag to retrieve: ' TAG
collect_tag "$TAG"
```

If you already have a platform manifest digest, skip tag discovery and call the
SBOM helper directly with that digest and its repository:

```bash
REPO='nginx'
read -r -p 'Platform manifest digest (sha256:...): ' DIGEST
fetch_sboms "$DIGEST" "$OUT/$REPO/$DIGEST"
```

For catalog-wide collection, configure the non-interactive credential option
and use the stripped repository list. This loop continues after failures and
returns an unsuccessful status if any repository, tag, or SBOM was not collected:

```bash
: "${DOCKER_NETRC:?Use non-interactive credentials for catalog collection}"
AUTH=(--netrc-file "$DOCKER_NETRC")
TOKEN=''
failures=0
while IFS= read -r REPO; do
  [[ "$REPO" =~ ^[a-z0-9-]+$ ]] || { printf 'Invalid repository name\n' >&2; exit 1; }
  mkdir -p "$OUT/$REPO"
  if ! list_tags "$OUT/$REPO/tags.txt"; then
    printf 'Tag discovery failed: %s\n' "$REPO" >&2
    failures=$((failures + 1))
    continue
  fi
  while IFS= read -r TAG; do
    if ! collect_tag "$TAG"; then
      printf 'Collection failed: %s:%s\n' "$REPO" "$TAG" >&2
      failures=$((failures + 1))
    fi
  done < "$OUT/$REPO/tags.txt"
done < repositories.txt
unset TOKEN
[[ "$failures" == 0 ]]
```

The loop can make many requests. Restrict `repositories.txt` and the tag list
for an initial trial, then schedule collection at an appropriate rate. No
parallelism is included. Treat inaccessible images and missing or ambiguous
attestations as collection failures rather than empty SBOMs. Catalog definitions
can include images or restricted variants unavailable to the selected account.

## Troubleshooting and references

- **401 after renewal:** check Docker credentials, scope, and access permissions.
  The helper retries only once; it does not hide persistent authorization errors.
- **403 or inaccessible restricted images:** check account entitlements and record
  the collection gap.
- **404 for a catalog tag:** definitions and publication may differ; record the
  missing tag and retry discovery later.
- **Multiple or missing SBOMs:** inspect the saved referrers response and choose
  an explicit policy before changing the sample's fail-on-ambiguity behavior.
- **Unexpected VEX matching results:** see the
  [current-production FAQ](current-production/docs/faq.md) or the
  [upcoming advisory-routing guide](upcoming-id-dhi/docs/advisory-routing.md).

References: [OCI Distribution specification](https://github.com/opencontainers/distribution-spec/blob/main/spec.md),
[image and attestation access](https://docs.docker.com/dhi/how-to/mirror/),
[DHI VEX](https://docs.docker.com/dhi/core-concepts/vex/), and
[scanning DHI images](https://docs.docker.com/dhi/how-to/scan/).
