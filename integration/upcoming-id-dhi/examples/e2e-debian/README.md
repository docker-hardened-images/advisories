# E2E Debian Fixture

This fixture models a future DHI Debian-family image after `/etc/os-release`
changes to:

```text
ID=dhi
ID_LIKE=debian
VERSION_ID=13
```

The source reference comes from the production definitions repository:

```text
dhi/bash:5.2.37-debian13@sha256:d34ec6dfa8a2faf4eb59f09452b9b133f29b9e785d304730bce00963e7dcd3c5
```

The advisory data is synthetic because generated DHI Debian OSV/VEX records are
not live yet.

## Files

| File | Purpose |
| --- | --- |
| `Dockerfile` | Builds a local synthetic image that overwrites `/etc/os-release` to `ID=dhi`. |
| `sbom.json` | Minimal SBOM-shaped fixture with a DHI Debian package PURL. |
| `osv/DHI-CVE-2025-70873-libsqlite3-0.json` | Synthetic OSV record for the DHI Debian package. |
| `vex/DHI-CVE-2025-70873-libsqlite3-0.json` | Synthetic OpenVEX context for the same advisory/package. |
| `expected.json` | Expected scanner-routing interpretation. |
