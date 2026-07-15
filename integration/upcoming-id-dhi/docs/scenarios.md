# Coverage Matrix

The upcoming validation harness uses static fixtures first and optional scanner
adapters second.

| Scenario | Fixture | What it proves |
| --- | --- | --- |
| Alpine `ID=dhi` OS package | [../examples/e2e-alpine](../examples/e2e-alpine/README.md) | A DHI APK package routes to generated DHI OSV and DHI VEX context. |
| Debian `ID=dhi` OS package | [../examples/e2e-debian](../examples/e2e-debian/README.md) | A DHI Debian package routes to generated DHI OSV and DHI VEX context. |
| `affected`, no fixed version | [../examples/scenarios/debian-affected-no-fixed](../examples/scenarios/debian-affected-no-fixed/) | A generated DHI OSV record with no fixed event creates an active finding, and VEX `affected` supplies context. This fixture is grounded in production `awscli` VEX data for `CVE-2026-21441`. |
| Fixed version excluded | [../examples/scenarios/alpine-fixed-version](../examples/scenarios/alpine-fixed-version/) | A package version outside the generated DHI OSV affected range produces no finding. VEX `fixed` is exact-product context, not a range inferred across versions. This fixture uses production Python advisory data for `CVE-2026-5713`; current production does not yet emit `fixed` VEX status. |
| `not_affected` | [../examples/scenarios/alpine-not-affected](../examples/scenarios/alpine-not-affected/) | A not-affected DHI assessment should normally produce no generated DHI OSV finding. Optional VEX explains the exact product state. This fixture is grounded in production Python VEX data for `CVE-2026-3298`. |
| DHI OS package with language component context | [../examples/scenarios/alpine-python-component](../examples/scenarios/alpine-python-component/) | The scanner match key remains the DHI OS package PURL, while language ecosystem package PURLs are component context. This fixture is grounded in production Python VEX data for `CVE-2025-12781`. |
| Later-layer OS package namespace | [../examples/e2e-alpine-layer-package-namespace](../examples/e2e-alpine-layer-package-namespace/README.md) | A package represented in the final APK database can be emitted as `pkg:apk/dhi/...` when the final image reports `ID=dhi`, even when the package metadata was added outside the DHI base. |
| Non-DHI-owned OS package | [../examples/scenarios/customer-added-upstream-apk](../examples/scenarios/customer-added-upstream-apk/) | A DHI namespace PURL is not enough to apply generated DHI advisory data. Scanner integrations need DHI product membership or provenance evidence. |
| Upstream PURL mismatch | [../validation/fixtures/scenarios.json](../validation/fixtures/scenarios.json) | A VEX product using `pkg:apk/alpine/...` or `pkg:deb/debian/...` is not considered sufficient context for a DHI artifact PURL. |
| Scanner-observed PURL | [../validation/fixtures/scenarios.json](../validation/fixtures/scenarios.json) | Adapter checks compare scanner output to the package PURL actually emitted by the scanner. |
| Mixed production | [../../migration/README.md](../../migration/README.md) | Current-production and upcoming `ID=dhi` handling coexist until all families are cut over. |
