# E2E Debian Snapshot Fixture

This fixture models a future DHI Debian-family image after `/etc/os-release`
changes to:

```text
ID=dhi
ID_LIKE=debian
VERSION_ID=13
```

The Dockerfile performs that rewrite only to simulate a pre-cutover image.
Production cutover images will contain this identity without scanner-side or
customer-side mutation.

The fixture is an immutable historical snapshot for `linux/arm64`:

```text
dhi/bash:5.2.37-debian13@sha256:d34ec6dfa8a2faf4eb59f09452b9b133f29b9e785d304730bce00963e7dcd3c5
```

Syft `1.46.0` observed `coreutils@9.7-3+dhi3` in that image. Production
advisories commit
[`67b6c12`](https://github.com/docker-hardened-images/advisories/commit/67b6c12a121bc04c225e9c4707912abcc4b022c2)
assesses `CVE-2017-18018` as `not_affected` for that exact Debian package
version. The local VEX file renders that historical assessment using the
upcoming DHI package namespace.

This fixture does not claim to represent current production. The image digest,
platform, advisory commit, package inventory, and observation date define the
snapshot.

## Files

| File | Purpose |
| --- | --- |
| `Dockerfile` | Builds a local synthetic image that overwrites `/etc/os-release` to `ID=dhi`. |
| `sbom.json` | Compact scanner snapshot with the local image ID, ordered image layers, and scanner-observed DHI Debian package evidence. |
| `vex/DHI-CVE-2017-18018-coreutils.json` | Upcoming-PURL rendering of the pinned production `not_affected` assessment. |
| `expected.json` | Expected scanner-routing interpretation. |
