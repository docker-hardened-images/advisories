# E2E Alpine Layer Package Namespace Fixture

This fixture demonstrates that scanner-observed OS package PURLs follow the
final image OS identity. The final image is a real DHI Alpine-family base whose
`/etc/os-release` is rewritten to the upcoming `ID=dhi` model. The fixture then
adds Alpine APK package metadata in a later layer.

The expected scanner observation is that the later-layer APK package is emitted
as `pkg:apk/dhi/jq@...`, even though the package metadata came from Alpine.
That proves the DHI package namespace is not enough, by itself, to establish DHI
product membership or advisory coverage.

## Files

| File | Purpose |
| --- | --- |
| `Dockerfile` | Builds a local image from a DHI Alpine base and adds later-layer APK package metadata. |
| `sbom.json` | Minimal SBOM-shaped fixture recording the expected scanner namespace. |
| `expected.json` | Expected interpretation: DHI namespace is observed, but DHI OSV is not automatically applicable without product membership. |
