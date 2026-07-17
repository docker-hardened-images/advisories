# Upcoming `ID=dhi` Validation Harness

The default validation mode is static and fast. It validates fixture structure,
package identity, OSV/VEX pairing, and scenario expectations without invoking a
scanner.

```bash
integration/upcoming-id-dhi/validation/run-fixture-suite.sh
```

Scanner-backed mode loads an adapter and runs local commands:

```bash
integration/upcoming-id-dhi/validation/run-fixture-suite.sh \
  --adapter integration/upcoming-id-dhi/validation/adapters/grype-adapter.sh \
  --run-scanner

integration/upcoming-id-dhi/validation/run-fixture-suite.sh \
  --adapter integration/upcoming-id-dhi/validation/adapters/docker-scout-adapter.sh \
  --run-scanner
```

## Adapter Contract

Adapters are shell files that define:

| Function | Purpose |
| --- | --- |
| `scanner_name` | Print a short scanner name. |
| `scanner_version` | Optionally print scanner and SBOM-tool versions for the run log. |
| `scanner_database_status` | Optionally print scanner database identity for the run log. |
| `scanner_preflight` | Verify required local commands are available. |
| `scanner_sbom_json TARGET OUTPUT` | Write scanner SBOM JSON for an image or archive target. |
| `scanner_scan_json TARGET OUTPUT` | Write scanner vulnerability JSON or SARIF for a target. |
| `scanner_scan_with_vex_json TARGET VEX OUTPUT` | Write scanner result after applying a VEX file. |

The harness does not publish advisory data. It is intended to validate local
scanner behavior while generated DHI OSV/VEX feeds are still pre-go-live.
Its fixture Dockerfiles rewrite `/etc/os-release` only to simulate future
cutover images. Production scanners must not perform that mutation.

## Reproducibility Contract

Scanner-backed fixtures are immutable, platform-specific image snapshots. The
manifest declares each source image by digest and the fixture platform, the
Dockerfile must use those exact references, and the recorded SBOM package
identity must match the scanner output. Use `--platform` only to require that
the selected snapshots match a particular platform; it does not retarget a
snapshot to another architecture.

Each compact scanner snapshot also records the local simulated image ID and an
ordered layer catalog. Static validation requires every package catalog/file
evidence reference to resolve to that catalog. For the derived-image fixture,
the ordered base layer digests must be an exact prefix of the derived layer
digests, inherited package files must retain base-layer evidence, and added
package files must have evidence outside the base.

Scanner vulnerability databases remain live inputs. Scanner-backed runs print
the UTC observation time and adapter-reported tool versions, and scanner result
formats may include additional database metadata. Retain the run log when using
the suite as evidence. The suite deliberately does not assert stable
vulnerability counts.

Static fixtures are marked `static-contract` and `image_snapshot: false`. They
exercise OSV/VEX and routing contracts from checked-in data; any mutable image
name is contextual source material, not a claim that the fixture can replay
that image state.

## Range And Provenance Responsibility

The generated DHI OSV examples in this guide are scanner-facing advisories for
DHI OS packages. Their `affected[].package.purl` values use
`pkg:apk/dhi/...` or `pkg:deb/dhi/...`, and their affected ranges use OSV
`ECOSYSTEM` ranges for the DHI OS package version.

Embedded language package PURLs, such as `pkg:pypi/...` or `pkg:npm/...`, are
component provenance for these examples. Component advisory range matching
happens before DHI feed generation, when the DHI advisory generation pipeline identifies affected DHI
packages from package-component associations. This harness therefore validates
that component PURLs are carried through OSV context, VEX subcomponents, and the
example SBOM parent-child relationship, but it does not evaluate component
ecosystem version ranges.

Scanner-backed mode builds each scanner-backed fixture image, runs the adapter
SBOM command, asserts that the output contains the expected DHI package PURL
prefix and every exact declared package identity, then runs the adapter scan
and, when provided by the fixture, scan-with-VEX commands. For the derived-image
scenario, it also builds and scans the pinned base fixture. The derived package
inventory must retain every base package and add exactly the declared `jq`
identity. Static-only scenario fixtures are validated by the default mode and
skipped by scanner-backed mode. Adapter commands must succeed, and their output
must be recognized SBOM, Grype JSON, or SARIF rather than an empty or arbitrary
file. The harness also fails when no scanner-backed scenario runs or the
executed count differs from the manifest.

The scanner-backed path does not assert final finding counts yet because Docker
Scout will not report the intended DHI findings until the generated advisory
data is available through the production advisory pipeline.

## Current Required Assertions

- OS packages observed under final `ID=dhi` can use `pkg:(apk|deb)/dhi/...`.
- DHI package namespace is scanner-observed identity, not proof of DHI product
  membership.
- Generated OSV affected package PURLs are versionless.
- Generated VEX product PURLs are versioned.
- The `os_distro` qualifier is validated as part of the fixture and generated
  feed shape; it is not a claim that the advisory pipeline currently uses `os_distro` as an
  advisory lookup key.
- Static validation derives expected findings from OSV affected ranges and the
  scenario package version instead of trusting fixture metadata alone.
- Generated VEX statements must point at the scenario package and, when an OSV
  fixture exists, the same DHI advisory.
- Component package PURLs are provenance: when declared, they must appear in
  OSV `database_specific.component_packages`, VEX product `subcomponents`, and
  the example SBOM with the DHI OS package as parent.
- DHI-layer packages do not require upstream Alpine/Debian OSV lookup once DHI
  OSV data exists.
- Active generated DHI OSV scenarios include `affected` and
  `under_investigation` VEX context.
- `fixed` and `not_affected` scenarios do not rely on post-match VEX
  suppression; the generated DHI OSV state should already produce no finding.
- DHI OS package advisories may reference language ecosystem component PURLs,
  but the scanner match key remains the DHI OS package PURL.
- Non-DHI-owned OS packages do not route to generated DHI OSV data from PURL
  namespace alone; product membership or provenance is required.
- In the derived-image fixture, base-SBOM membership routes inherited
  `coreutils` to DHI OSV while excluding the added `jq` package absent separate
  DHI provenance, even though both scanner PURLs use the DHI namespace.
- Scanner snapshot layer catalogs are ordered and self-contained: package
  evidence cannot reference an undeclared layer, and the derived base digest
  prefix must match the standalone base snapshot exactly.
- Scanner-backed VEX checks must use the package PURL that the scanner actually
  reports, unless the scanner documents canonicalization.
