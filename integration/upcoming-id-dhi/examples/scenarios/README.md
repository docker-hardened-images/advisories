# Static Scenario Fixtures

These fixtures cover scanner behavior that does not need to be duplicated for
both Alpine and Debian image builds. The validation harness checks them in
static mode through
[`../../validation/fixtures/scenarios.json`](../../validation/fixtures/scenarios.json).

The examples are grounded in current production advisory data where possible.
They are static contract fixtures, not runnable or immutable image snapshots;
mutable image names are recorded only as contextual production references. The
`pkg:(apk|deb)/dhi/...` PURLs are the upcoming `ID=dhi` target identity, and
each fixture records its production anchor in `expected.json`.

| Scenario | Fixture | Production anchor |
| --- | --- | --- |
| `affected`, no fixed version | [debian-affected-no-fixed](debian-affected-no-fixed/) | `CVE-2025-12781` from pinned Python definitions and VEX snapshots, rendered for the Debian `python-3.9` package. |
| Fixed version excluded | [alpine-fixed-version](alpine-fixed-version/) | `CVE-2026-5713` from Python OSV/VEX data; current production does not yet emit `fixed` VEX status. |
| `not_affected` | [alpine-not-affected](alpine-not-affected/) | `CVE-2026-3298` from Python VEX data. |
| DHI OS package with language component context | [alpine-python-component](alpine-python-component/) | `CVE-2025-12781` from Python VEX data, with `pkg:pypi/setuptools@58.3.0` as component context. |
| Non-DHI-owned OS package | [customer-added-upstream-apk](customer-added-upstream-apk/) | Current Python APK product shape used as the product membership boundary. |
