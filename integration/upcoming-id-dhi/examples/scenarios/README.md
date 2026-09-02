# Static Scenario Fixtures

These fixtures cover scanner behavior that does not need to be duplicated for
both Alpine and Debian image builds. The validation harness checks them in
static mode through
[`../../validation/fixtures/scenarios.json`](../../validation/fixtures/scenarios.json).

The examples use pinned production advisory data as source evidence where
possible. They are static contract fixtures, not runnable or immutable image
snapshots. Source evidence and production anchors are recorded in
`expected.json` and the validation manifest; they are fixture provenance, not
fields in the target OSV or VEX payloads. The
`pkg:(apk|deb)/dhi/...` PURLs are the upcoming `ID=dhi` target identity.

| Scenario | Fixture | Fixture basis |
| --- | --- | --- |
| `affected`, no fixed version | [debian-affected-no-fixed](debian-affected-no-fixed/) | `CVE-2025-12781` from pinned Python definitions and VEX snapshots, rendered for the Debian `python-3.9` package. |
| Fixed version excluded | [alpine-fixed-version](alpine-fixed-version/) | `CVE-2026-5713` rendered with target `fixed` VEX context for an exact DHI package version. |
| `not_affected` | [alpine-not-affected](alpine-not-affected/) | `CVE-2026-3298` from Python VEX data. |
| `under_investigation` with language component context | [alpine-python-component](alpine-python-component/) | DHI OSV lists `python-3.12@3.12.13-r7` as affected without defining a range, while Python VEX marks the assessment unresolved; `pkg:pypi/setuptools@58.3.0` remains component context. |
| Non-DHI-owned OS package | [customer-added-upstream-apk](customer-added-upstream-apk/) | A package identified as customer-layer content does not route to DHI advisory data solely because its scanner PURL uses the DHI namespace; it uses normal upstream Alpine coverage instead. |
