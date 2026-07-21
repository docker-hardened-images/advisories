# E2E Alpine Snapshot Fixture

This fixture models a future DHI Alpine-family image after `/etc/os-release`
changes to:

```text
ID=dhi
ID_LIKE=alpine
VERSION_ID=3.24
```

The Dockerfile performs that rewrite only to simulate a pre-cutover image.
Production cutover images will contain this identity without scanner-side or
customer-side mutation.

The fixture is an immutable historical snapshot for `linux/arm64`:

```text
dhi.io/bash:5-alpine3.24@sha256:e2b67997780c37dc8352fb3e1bae077497216767cd5edb25c710e3a0fef232ec
```

Syft `1.46.0` observed `coreutils@9.11-r0` in that image after changing only
`/etc/os-release`. The synthetic vulnerability example uses the Grype
exploration target from the cutover tooling:

```text
CVE-2016-2781 on coreutils@9.11-r0
```

The package identity is scanner-observed from the pinned image. The advisory
content models the pre-go-live DHI feed shape; it is not a production DHI
assessment. Scanner vulnerability databases remain live inputs when this
fixture is exercised, so the scanner-backed harness validates package identity
and valid scanner output rather than a stable finding count.

## Files

| File | Purpose |
| --- | --- |
| `Dockerfile` | Builds a local synthetic image that overwrites `/etc/os-release` to `ID=dhi`. |
| `sbom.json` | Compact scanner snapshot with the local image ID, ordered image layers, and scanner-observed DHI APK package evidence. |
| `osv/DHI-CVE-2016-2781-coreutils.json` | Synthetic OSV record for the DHI APK package. |
| `vex/DHI-CVE-2016-2781-coreutils.json` | Synthetic OpenVEX context for the same advisory/package. |
| `expected.json` | Expected scanner-routing interpretation. |

The generated production feed will use real DHI advisory IDs from the
materialization pipeline. The fixture ID is intentionally readable for local
validation.
