# Coverage Matrix

The upcoming validation harness uses static fixtures first and optional scanner
adapters second.

| Scenario | Fixture | What it proves |
| --- | --- | --- |
| Alpine `ID=dhi` OS package | [../examples/e2e-alpine](../examples/e2e-alpine/README.md) | A DHI APK package routes to generated DHI OSV and DHI VEX context. |
| Debian `ID=dhi` OS package (not_affected) | [../examples/e2e-debian](../examples/e2e-debian/README.md) | A DHI Debian package assessed not_affected produces no finding because generated DHI OSV excludes the package/version. Docker publishes the not_affected VEX as exact-product context; scanners may choose whether to consume it. |
| `affected`, no fixed version | [../examples/scenarios/debian-affected-no-fixed](../examples/scenarios/debian-affected-no-fixed/) | A generated DHI OSV record with an open-ended affected range and a resolved exact affected version creates an active finding. Published VEX `affected` supplies exact-product status and action context. |
| Fixed version excluded | [../examples/scenarios/alpine-fixed-version](../examples/scenarios/alpine-fixed-version/) | A package version that is neither explicitly listed nor inside the generated DHI OSV affected range produces no finding. Published VEX `fixed` context applies only to the exact product version. |
| `not_affected` | [../examples/scenarios/alpine-not-affected](../examples/scenarios/alpine-not-affected/) | A `not_affected` DHI assessment produces no generated DHI OSV finding for the package/version. The published VEX record explains the exact product state whether or not a scanner consumes it. |
| `under_investigation` with language component context | [../examples/scenarios/alpine-python-component](../examples/scenarios/alpine-python-component/) | An exact version enumerated by conservative generated DHI OSV coverage creates a finding without requiring VEX or inventing a range. Matching VEX supplies the unresolved assessment status, and the language ecosystem package PURL remains component context rather than the scanner match key. |
| Derived-image package routing | [../examples/e2e-alpine-layer-package-namespace](../examples/e2e-alpine-layer-package-namespace/README.md) | Both inherited `coreutils` and later-layer `jq` are emitted as `pkg:apk/dhi/...`; recorded base membership and package layer attribution route `coreutils` to generated DHI advisory data and `jq` to normal upstream Alpine coverage. The fixture models the classification inputs without retrieving an OCI-referrer SBOM. |
| Non-DHI-owned OS package | [../examples/scenarios/customer-added-upstream-apk](../examples/scenarios/customer-added-upstream-apk/) | A DHI namespace PURL is not enough to apply generated DHI advisory data. A package that is neither attributed to DHI base layers nor matched against a known base's Docker-issued SBOM is normalized to its upstream Alpine identity and uses normal upstream coverage. |
| Upstream PURL mismatch | [../validation/fixtures/scenarios.json](../validation/fixtures/scenarios.json) | A VEX product using `pkg:apk/alpine/...` or `pkg:deb/debian/...` is not considered sufficient context for a DHI artifact PURL. |
| Scanner-observed PURL | [../validation/fixtures/scenarios.json](../validation/fixtures/scenarios.json) | Adapter checks compare scanner output to the package PURL actually emitted by the scanner. |
| Mixed production | [../../migration/README.md](../../migration/README.md) | Current-production and upcoming `ID=dhi` handling coexist until all families are cut over. |
