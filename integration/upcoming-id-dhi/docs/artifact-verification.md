# Verifying Published Artifacts

Generated DHI OSV records and VEX documents are signed with a Docker-controlled
OpenPGP key. This page explains how a scanner or importer can confirm that an
artifact it fetched was published by Docker, unchanged, at the path it was
fetched from.

Generated artifacts live under `dhi/osv/` and `dhi/vex/`. They do not use the
Cosign signatures documented in the [repository README](../../../README.md) for
the `osv/` and `vex/` trees; see
[Relationship to Cosign signatures](#relationship-to-cosign-signatures).

## What Is Signed

Two independent things are signed:

- **Every commit** that publishes generated artifacts. A commit signature covers
  the whole repository tree at that commit, every path and every byte.
- **Every artifact**, through five files published beside it:

```text
dhi/osv/DHI-vdvh-b7bo-zxsy-xxkb.json             the OSV record
dhi/osv/DHI-vdvh-b7bo-zxsy-xxkb.json.asc         signature over the record
dhi/osv/DHI-vdvh-b7bo-zxsy-xxkb.json.sha256      SHA-256 checksum line
dhi/osv/DHI-vdvh-b7bo-zxsy-xxkb.json.sha256.asc  signature over the checksum line
dhi/osv/DHI-vdvh-b7bo-zxsy-xxkb.json.sha512      SHA-512 checksum line
dhi/osv/DHI-vdvh-b7bo-zxsy-xxkb.json.sha512.asc  signature over the checksum line
```

VEX documents under `dhi/vex/` carry the same five files. An advisory can be
VEX-only; it then has no file under `dhi/osv/`.

A checksum file holds one line in coreutils format: the hex digest, two spaces,
and the artifact's path relative to the repository root.

```text
16b7492f…  dhi/osv/DHI-vdvh-b7bo-zxsy-xxkb.json
```

## Signing Key

| Property | Value |
| --- | --- |
| Algorithm | OpenPGP v4, EdDSA (Ed25519) |
| User ID | `dhi-bot <dhi@docker.com>` |
| Fingerprint | `3C03 F4C0 3E93 7E46 9287  DADA 7444 3225 FBB3 4CE4` |
| Expires | 2027-09-04 |
| Public key | `<PUBLIC-KEY-URL>` |

<!-- TODO: replace <PUBLIC-KEY-URL> once the public key location is decided,
and list retired keys with their validity periods there. -->

Pin the fingerprint, not just the user ID or the key file. A signature from any
other key, even one claiming `dhi@docker.com`, must be rejected.

The key is rotated before it expires. Retired public keys remain published at
the same location with the period each one was in use, so older artifacts stay
verifiable; see [Verifying older artifacts](#verifying-older-artifacts).

The creation time on an artifact signature is the artifact's own lifecycle
timestamp (the OSV `modified` or VEX `last_updated` value), not the time it was
signed. This keeps signatures byte-identical when an unchanged artifact is
republished. Do not treat it as evidence of when the signature was made.

## Choosing a Verification Route

| Route | Binds | Use it when |
| --- | --- | --- |
| [Checksum route](#checksum-route) (`.sha256` + `.sha256.asc`, or SHA-512) | The artifact's content **and** its path | You fetch individual files and need to trust an artifact at a given path. **Recommended.** |
| [Artifact signature](#artifact-signature) (`.json.asc`) | The artifact's content only | You only need to know that Docker signed these bytes. |
| [Commit signature](#commit-signature) | The whole tree at one commit | You clone the repository or a full snapshot of it. |

The two per-artifact routes are not equivalent. A detached OpenPGP signature
cannot record a path, and advisory IDs repeat across `dhi/osv/` and `dhi/vex/`,
so a valid `.json.asc` cannot tell an OSV record from the VEX document of the
same advisory. The checksum line names the path, and its signature covers that
line.

## Checksum Route

A correct check has four parts, and each one matters:

1. The signature on the checksum file is good **and** was made by the pinned
   fingerprint.
2. The key is not revoked. `gpg --verify` exits 0 for a signature from a
   revoked key, so check its status output rather than its exit code.
3. The checksum line names exactly the path you fetched, and the file has no
   other lines. `sha256sum -c` checks whatever file the line names.
4. The digest you compute yourself from the artifact equals the signed digest.

Fetch every file from one commit, not from a branch name, so the files cannot
straddle a publish. This script does all of the above for one artifact; it
needs `bash`, `curl`, `git` and `gpg`:

```bash
#!/usr/bin/env bash
# Verify one DHI OSV or VEX artifact through its signed checksum files.
# usage: verify-dhi-artifact.sh <ref> <artifact-path> <public-key.asc>
set -euo pipefail

repo=docker-hardened-images/advisories
expected_fpr=3C03F4C03E937E469287DADA74443225FBB34CE4
ref=$1 path=$2 key=$3

case "$path" in
  dhi/osv/*.json | dhi/vex/*.json) ;;
  *) echo "error: expected dhi/osv/<id>.json or dhi/vex/<id>.json" >&2; exit 2 ;;
esac

# Resolve the ref once so every file comes from the same commit.
commit=$(git ls-remote "https://github.com/$repo" "$ref" | awk 'NR==1 {print $1}')
if [ -z "$commit" ]; then
  commit=$ref
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
export GNUPGHOME="$work/gnupg"
mkdir -m 700 "$GNUPGHOME"
gpg --batch --quiet --import "$key"

fetch() {
  mkdir -p "$work/$(dirname "$1")"
  curl -fsSL "https://raw.githubusercontent.com/$repo/$commit/$1" -o "$work/$1"
}

# Accept only a good signature whose primary key is the pinned key.
# gpg exits 0 for a revoked key, so check the status lines instead.
check_sig() {
  local status
  status=$(gpg --batch --status-fd 1 --verify "$work/$1" "$work/$2" 2>/dev/null || true)
  grep -q '^\[GNUPG:\] GOODSIG ' <<<"$status" || { echo "FAIL: no good signature on $2" >&2; exit 1; }
  awk '$2 == "VALIDSIG" {print $NF}' <<<"$status" | grep -qx "$expected_fpr" ||
    { echo "FAIL: $2 is not signed by $expected_fpr" >&2; exit 1; }
}

fetch "$path"
for alg in sha256 sha512; do
  fetch "$path.$alg"
  fetch "$path.$alg.asc"
  check_sig "$path.$alg.asc" "$path.$alg"

  # The signed line must name exactly this path, so it can't vouch for another file.
  read -r digest named < "$work/$path.$alg"
  [ "$named" = "$path" ] || { echo "FAIL: $path.$alg names $named" >&2; exit 1; }
  [ "$(wc -l < "$work/$path.$alg")" -eq 1 ] || { echo "FAIL: $path.$alg has extra lines" >&2; exit 1; }

  actual=$("${alg}sum" "$work/$path" | awk '{print $1}')
  [ "$actual" = "$digest" ] || { echo "FAIL: $alg digest mismatch for $path" >&2; exit 1; }
done

echo "OK: $path at $commit is signed by $expected_fpr"
```

```bash
./verify-dhi-artifact.sh main dhi/osv/DHI-vdvh-b7bo-zxsy-xxkb.json dhi-bot.pub.asc
```

`GOODSIG` is absent for an expired or revoked key, so the script rejects both.
On macOS, install GNU coreutils for `sha256sum` and `sha512sum`, or replace
them with `shasum -a 256` and `shasum -a 512`.

The same check by hand, from the root of a clone:

```bash
export GNUPGHOME=$(mktemp -d) && gpg --import dhi-bot.pub.asc
f=dhi/osv/DHI-vdvh-b7bo-zxsy-xxkb.json

gpg --status-fd 1 --verify "$f.sha256.asc" "$f.sha256" | grep -E 'GOODSIG|VALIDSIG|REVKEYSIG|EXPKEYSIG'
# Expect GOODSIG, and VALIDSIG ending in 3C03F4C03E937E469287DADA74443225FBB34CE4

cat "$f.sha256"      # must name exactly $f, on a single line
sha256sum -c "$f.sha256"
```

Prefer `sha256sum -c` over `shasum -a 256 -c`: `shasum -c` infers the
algorithm from the digest length and ignores `-a`, so it does not prove which
algorithm was checked.

## Artifact Signature

`<artifact>.asc` is a detached signature over the artifact's bytes, for a
one-step check:

```bash
gpg --status-fd 1 --verify "$f.asc" "$f" | grep -E 'GOODSIG|VALIDSIG|REVKEYSIG|EXPKEYSIG'
```

Apply the same fingerprint and revocation checks as above. A good result means
Docker signed these bytes. It does not mean they belong at this path: the VEX
document of an advisory, served at its OSV path with its own `.asc`, verifies.
Use the checksum route when the path matters.

## Commit Signature

A signed commit binds every path and byte in the tree it records, including the
sidecars.

This repository has more than one writer: generated artifacts are committed by
the DHI advisory publisher, while other trees are maintained by other processes
signing with other keys. The latest commit on a branch may not be one of the
publisher's. Verify the commit that last changed the artifact you care about:

```bash
repo=docker-hardened-images/advisories
f=dhi/osv/DHI-vdvh-b7bo-zxsy-xxkb.json

commit=$(curl -fsSL "https://api.github.com/repos/$repo/commits?sha=main&path=$f&per_page=1" | jq -r '.[0].sha')
curl -fsSL "https://api.github.com/repos/$repo/commits/$commit" > commit.json

# 1. GitHub verified the signature when the commit was pushed
jq '.commit.verification | {verified, reason, verified_at}' commit.json

# 2. ...and the signing key is the pinned one
jq -r '.commit.verification.signature' commit.json | gpg --list-packets 2>/dev/null | grep 'issuer fpr'
# Expect: hashed subpkt 33 len 21 (issuer fpr v4 3C03F4C03E937E469287DADA74443225FBB34CE4)
```

Both checks are needed. `verified: true` means the signature matches a key
registered to the signing GitHub account, and that account holds more than one
key, so it does not identify which one.

In a clone with the public key imported, `git verify-commit` gives the same
answer as the second check:

```bash
git verify-commit --raw "$commit" 2>&1 | grep -E 'GOODSIG|VALIDSIG'
```

GitHub verifies a commit when it is pushed and records the result, with the
time, in `verified_at`. That record is the timestamp to rely on. A commit's own
date, like an artifact signature's, is chosen by the signer, so `git
verify-commit` on its own proves which key signed the commit but not when.

A verified commit vouches for the whole tree it records, including files it
inherited from earlier commits written by other processes. Rely on it for the
paths that commit changed; for the rest of the tree, it is only as strong as
the history before it.

## Verifying Older Artifacts

The checksum and artifact routes reject expired keys. A signer chooses its
signature timestamps, so a signature cannot show that it was made before the
key expired; anyone holding a retired private key could sign today and date it
in the past.

To verify an artifact published under a retired key, verify the commit that
published it through GitHub's verification record, which was made when the
commit was pushed. GitHub keeps that record for keys that remain registered to
the signer, and retired keys stay registered.

## Limits

- Sidecars carry no version. Serving an older, genuinely signed artifact and
  its sidecars at the same path passes both per-artifact routes. Only the commit
  signature shows that an artifact is the current one.
- A verified artifact says nothing about the rest of the tree, for example
  whether another artifact was removed.
- Verification shows that Docker published an artifact. It does not validate
  the artifact's content; scanners still apply the routing and matching rules in
  [Advisory routing](advisory-routing.md).

## Relationship to Cosign Signatures

| Trees | Signature files | Mechanism | Key |
| --- | --- | --- | --- |
| `osv/`, `vex/` | `.sig` | Cosign Sigstore bundle | `https://registry.scout.docker.com/keyring/dhi/latest` |
| `dhi/osv/`, `dhi/vex/` | `.asc` | Detached OpenPGP signature | [Signing key](#signing-key) |

The extension tells you which applies: a `.sig` beside an artifact is a Cosign
bundle, and an `.asc` is an OpenPGP signature. The two use different keys, and
neither verifies the other's files.
