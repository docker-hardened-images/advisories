# E2E Alpine Fixture

This fixture models a future DHI Alpine-family image after `/etc/os-release`
changes to:

```text
ID=dhi
ID_LIKE=alpine
VERSION_ID=3.24
```

The source family is the same one used by the local cutover tooling:

```text
dhi.io/bash:5-alpine3.24
```

The vulnerability example uses the Grype exploration target from the cutover
tooling:

```text
CVE-2016-2781 on coreutils@9.11-r0
```

## Files

| File | Purpose |
| --- | --- |
| `Dockerfile` | Builds a local synthetic image that overwrites `/etc/os-release` to `ID=dhi`. |
| `sbom.json` | Minimal SBOM-shaped fixture with a DHI APK package PURL. |
| `osv/DHI-CVE-2016-2781-coreutils.json` | Synthetic OSV record for the DHI APK package. |
| `vex/DHI-CVE-2016-2781-coreutils.json` | Synthetic OpenVEX context for the same advisory/package. |
| `expected.json` | Expected scanner-routing interpretation. |

The generated production feed will use real DHI advisory IDs from the
materialization pipeline. The fixture ID is intentionally readable for local
validation.
