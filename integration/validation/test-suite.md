# DHI Scanner Integration: Test Suite

This test suite validates that your scanner correctly integrates with Docker Hardened Images.

## Overview

Tests are organized into 4 levels:

- **Level 1**: Basic Detection & VEX
- **Level 2**: Package Routing
- **Level 3**: Derived Images
- **Level 4**: Edge Cases

Exact CVE IDs and some package versions change over time as advisory data evolves.  
The validation target is scanner behavior (routing, matching, suppression), not a fixed CVE list.
The reference harness defaults to `linux/arm64` and pins arm64 manifest digests for its built-in validation images.

Use the certification requirements below to determine DHI Scanner Certification eligibility.

---

## Validation Requirements

The following are the required behaviors this validation suite checks:

- **R1**: VEX must be loaded from OCI referrer attestations on the image digest.
- **R2**: When scanning a DHI image, scanner logic must include DHI OSV consideration for all packages (not only `pkg:dhi/*`).
- **R3**: For distro packages in DHI images, scanner behavior must combine upstream advisory routing with DHI VEX application.
- **R4**: Referrers are looked up via image digest; chainID is used only for base-boundary classification (not as a referrer lookup key).

**Requirement-to-Test Mapping**:

- **R1**: Test 1.3
- **R2**: Tests 2.1 and 2.2
- **R3**: Tests 2.2 and 3.3
- **R4**: Tests 1.3, 3.1, and 3.2

---

## Level 1: Basic Integration

### Test 1.1: Identify DHI Image ✓

**Image**: `dhi.io/python:3.13-alpine3.23@sha256:219ee56599402640c694fd41fce8b009b6abcfc63e05d74239010024af94e9be`

**Steps**:
1. Run scanner on image
2. Check that scanner identifies as DHI image

**Expected**:
```bash
$ your-scanner scan dhi.io/python:3.13-alpine3.23@sha256:219ee56599402640c694fd41fce8b009b6abcfc63e05d74239010024af94e9be --format json | jq '.is_dhi'
true
```

**Validation**: Scanner detects `/etc/os-release` contains "Docker Hardened Images"

---
### Test 1.2: Retrieve SBOM ✓

**Image**: `dhi.io/python:3.13-alpine3.23@sha256:219ee56599402640c694fd41fce8b009b6abcfc63e05d74239010024af94e9be`

**Steps**:
1. Scanner retrieves SBOM (via OCI referrers or filesystem)
2. SBOM contains ~30-40 packages

**Expected**: Scanner finds key packages:
- `pkg:dhi/python@3.13.1`
- `pkg:apk/alpine/musl@*`
- Various Alpine system packages
**Validation**:
```bash
$ your-scanner scan dhi.io/python:3.13-alpine3.23@sha256:219ee56599402640c694fd41fce8b009b6abcfc63e05d74239010024af94e9be --show-packages | grep "pkg:dhi/python"
pkg:dhi/python@3.13.1
```

---

### Test 1.3: Load and Parse VEX ✓

**Image**: `dhi.io/bash:5@sha256:55ca1da07f8332342db5224144e7455d68a2864645f1c1b7ee5f1324f11cce84` (reference harness default arm64 manifest; any image with attached OpenVEX attestation is valid)

**Steps**:
1. Scanner resolves the image digest
2. Scanner loads VEX from OCI referrer attestation
3. Scanner parses OpenVEX format
4. Scanner indexes VEX by CVE + PURL

**Expected**: Scanner loads VEX containing statements like:
```json
{
  "vulnerability": {"name": "CVE-YYYY-NNNN"},
  "products": [{"@id": "pkg:dhi/<package>@<version>"}],
  "status": "not_affected"
}
```

**Validation**: Check scanner can look up VEX for specific CVE+PURL

---

### Test 1.4: Apply Basic VEX ✓

**Image**: `dhi.io/python:3.13-alpine3.23@sha256:219ee56599402640c694fd41fce8b009b6abcfc63e05d74239010024af94e9be`
**CVE**: Any discovered CVE in `pkg:dhi/python@<version>`

**Steps**:
1. Scanner finds a Python CVE via OSV feed
2. Scanner matches VEX statement
3. Scanner suppresses CVE based on VEX status

**Expected Output**:
```json
{
  "cve": "CVE-YYYY-NNNN",
  "package": "pkg:dhi/python@<version>",
  "severity": "HIGH",
  "status": "not_affected",
  "vex_applied": true
}
```

**Validation**: CVE marked as not_affected, not reported as exploitable

---

## Level 2: Package Routing

### Test 2.1: Route DHI Package to OSV ✓

**Image**: `dhi.io/python:3.13-alpine3.23@sha256:219ee56599402640c694fd41fce8b009b6abcfc63e05d74239010024af94e9be`
**Package**: `pkg:dhi/python@3.13.1`

**Steps**:
1. Scanner identifies package namespace as `dhi`
2. Scanner queries DHI OSV feed
3. Scanner also checks DHI OSV feed for all packages when scanning a DHI image
4. Scanner does NOT check Debian/Alpine/PyPI databases for `pkg:dhi/*`

**Expected**: Scanner uses:
- `https://github.com/docker-hardened-images/advisories/osv/python/`

**Validation**:
```bash
# Scanner should NOT report CVEs from Alpine Python package
# Scanner should ONLY report CVEs from DHI OSV feed
```

**Anti-Pattern**: Scanner checks Alpine Linux CVE database for `pkg:dhi/python` → FAIL

---

### Test 2.2: Route Distro Package to Upstream + VEX ✓

**Image**: `dhi.io/python:3.13-alpine3.23@sha256:219ee56599402640c694fd41fce8b009b6abcfc63e05d74239010024af94e9be`
**Package**: `pkg:apk/alpine/openssl@<version>`

**Steps**:
1. Scanner identifies package as Alpine package
2. Scanner shows upstream Alpine source routing marker in vulnerability output
3. Scanner applies matching VEX and marks the CVE as not_affected

**Expected Validation Flow**:
```
1. Scan distro package CVEs and confirm Alpine routing marker
2. Apply matching VEX statement for the discovered distro package CVE
3. Confirm the CVE is marked not_affected
```

**Validation**: Upstream routing marker is present and VEX status is applied to the discovered CVE.
This is the required observable behavior for distro package handling in DHI scans (R2/R3), even though scanner-internal feed query ordering is implementation-specific.

---

### Test 2.3: Route Application Package to Standard Sources ✓

**Image**: Derived image with `pkg:pypi/flask@2.3.0`

**Steps**:
1. Scanner identifies as application package
2. Scanner uses standard sources (PyPI, GitHub Advisories)
3. Scanner does NOT apply DHI VEX

**Expected**: Flask CVEs reported normally, no DHI VEX applied

**Validation**: Customer packages scanned independently

---

## Level 3: Derived Images

### Test 3.1: Detect Derived Image ✓

**Image**: Built FROM `dhi.io/python:3.13-alpine3.23@sha256:219ee56599402640c694fd41fce8b009b6abcfc63e05d74239010024af94e9be`

**Dockerfile**:
```dockerfile
FROM dhi.io/python:3.13-alpine3.23@sha256:219ee56599402640c694fd41fce8b009b6abcfc63e05d74239010024af94e9be
RUN pip install flask==2.3.0
```

**Steps**:
1. Build derived image
2. Scanner checks labels
3. Scanner finds `com.docker.dhi.chain-id`

**Expected**:
```bash
$ your-scanner scan derived-image --format json | jq '.is_derived'
true

$ your-scanner scan derived-image --format json | jq '.chain_id'
"sha256:ad3d5af2b712a318..."
```

**Validation**: Scanner detects this is a DHI-derived image

---

### Test 3.2: Differentiate Base and Customer Packages ✓

**Image**: Derived from `dhi.io/python:3.13-alpine3.23@sha256:219ee56599402640c694fd41fce8b009b6abcfc63e05d74239010024af94e9be`

**Steps**:
1. Build the derived image
2. Retrieve SBOM for the derived image
3. Confirm SBOM contains representative DHI base package and customer-added package
4. Use chainID metadata only to classify base/customer boundaries (not to perform referrer lookup)

**Expected**: Scanner output includes both base and customer package identities:
```json
{
  "packages": [
    {"purl": "pkg:dhi/python@3.13.1"},
    {"purl": "pkg:pypi/flask@2.3.0"},
    ...
  ]
}
```

**Validation**: Scanner can differentiate base (`pkg:dhi/...`) from customer (`pkg:pypi/...`) packages in the derived image SBOM.
Digest-based referrer behavior is validated in Test 1.3; chainID boundary usage is validated in Tests 3.1/3.2.

---

### Test 3.3: Apply VEX Only to Base Packages ✓

**Image**: Derived with Flask added

**Packages**:
- `pkg:dhi/python@3.13.1` (from base)
- `pkg:pypi/flask@2.3.0` (customer-added)

**CVEs**:
- one CVE in Python
- one CVE in Flask

**Expected Behavior**:
| Package | CVE | In Base? | Apply VEX? | Result |
|---------|-----|----------|-----------|--------|
| Python | CVE-YYYY-NNNN | ✅ Yes | ✅ Yes | Suppressed |
| Flask | CVE-YYYY-NNNN | ❌ No | ❌ No | Reported |

**Validation**:
```json
{
  "vulnerabilities": [
    {
      "cve": "CVE-YYYY-NNNN",
      "package": "pkg:dhi/python@<version>",
      "status": "not_affected",
      "vex_applied": true
    },
    {
      "cve": "CVE-YYYY-NNNN",
      "package": "pkg:pypi/flask@<version>",
      "status": "vulnerable",
      "vex_applied": false
    }
  ]
}
```

**Anti-Pattern**: Flask gets DHI VEX applied → FAIL (false negative)

---

## Level 4: Edge Cases

### Test 4.1: Multi-Stage Build (DHI as Builder) ✓

**Dockerfile**:
```dockerfile
FROM dhi.io/python:3.13-alpine3.23@sha256:219ee56599402640c694fd41fce8b009b6abcfc63e05d74239010024af94e9be AS builder
RUN ["python", "-c", "open('/tmp/marker.txt','w').write('edge-4-1')"]

FROM alpine:3.21
COPY --from=builder /tmp/marker.txt /app/marker.txt
```

**Expected**:
- Final image has NO DHI packages
- No chainID label present
- No DHI VEX should apply

**Validation**: Scanner treats final image as regular Alpine, not DHI

---

### Test 4.2: Customer Replaces DHI Package ✓

**Scenario**: Customer removes DHI Python and installs Alpine Python

**Dockerfile**:
```dockerfile
FROM alpine:3.23 AS apkpy
RUN apk add --no-cache python3 py3-pip

FROM dhi.io/python:3.13-alpine3.23@sha256:219ee56599402640c694fd41fce8b009b6abcfc63e05d74239010024af94e9be
USER 0
RUN ["python", "-c", "import os,shutil; paths=['/opt/python','/opt/python-3.13.11','/opt/docker/sbom/dhi-pkg-python','/opt/docker/sbom/dhi-python','/opt/docker/sbom/python'];\nfor p in paths:\n  if os.path.islink(p): os.unlink(p)\n  elif os.path.isdir(p): shutil.rmtree(p, ignore_errors=True)\n  elif os.path.exists(p): os.remove(p)"]
COPY --from=apkpy /lib/apk /lib/apk
COPY --from=apkpy /etc/apk /etc/apk
COPY --from=apkpy /usr/bin/python3 /usr/bin/python3
COPY --from=apkpy /usr/lib/python3.12 /usr/lib/python3.12
COPY --from=apkpy /usr/lib/libpython3.12.so.1.0 /usr/lib/libpython3.12.so.1.0
USER 65532
```

**Expected**:
- PURL changes from `pkg:dhi/python@<version>` to `pkg:apk/alpine/python3@<version>`
- `pkg:dhi/python@<version>` is no longer present after replacement
- VEX for `pkg:dhi/python` won't match
- Scanner treats as Alpine package

**Validation**: No DHI VEX applied to replaced package

---

### Test 4.3: Version Mismatch ✓

**Scenario**: VEX targets one package version, image contains a different version

**VEX Statement**:
```json
{
  "vulnerability": {"name": "CVE-YYYY-NNNN"},
  "products": [{"@id": "pkg:dhi/python@A.B.C"}]
}
```

**Image Has**: `pkg:dhi/python@X.Y.Z`

**Expected**: VEX does NOT match (version differs), CVE reported normally

**Validation**: Scanner requires exact version match

---

### Test 4.4: No OSV Directory Exists ✓

**Package**: `pkg:dhi/bash@<version>`

**OSV Query**:
```bash
$ curl https://.../osv/bash/
# Returns: 404 Not Found
```

**Expected**: Scanner interprets 404 as "no active vulnerabilities"

**Validation**: Scanner doesn't report false "cannot determine" status

---

### Test 4.5: PURL Format Variations ✓

**VEX May Include Multiple PURL Formats**:
```json
{
  "products": [
    {"@id": "pkg:deb/debian/util-linux@2.41-5"},
    {"@id": "pkg:deb/debian/util-linux@2.41-5?os_distro=trixie&os_name=debian&os_version=13"}
  ]
}
```

**Expected**: Scanner handles both formats, matches against either

**Validation**: Scanner normalizes or checks all PURL variations

---

## Automated Validation

`validation/run-test-suite.sh` is a **reference harness** that uses Docker Scout by default.

Scanner behavior is provided by an adapter file.

- Default adapter: `validation/adapters/docker-scout-adapter.sh`
- Required local commands to run the harness as-is: `docker` and `jq`
- Additional requirement for default adapter: `docker scout`

To use another scanner:
1. Create an adapter file that implements the required functions below
2. Run the harness with `--adapter /path/to/your-adapter.sh`

Required adapter functions:

- `scanner_sbom_list`
- `scanner_sbom_json`
- `scanner_cves`
- `scanner_cves_with_vex`
- `scanner_detect_dhi`
- `scanner_vex_get`

The harness exports `DHI_TARGET_PLATFORM` to adapters. The default Scout adapter also passes that platform to `docker scout --platform`.

### Run Full Test Suite

```bash
cd validation
./run-test-suite.sh
```

### Run Specific Level

```bash
./run-test-suite.sh --level 1
./run-test-suite.sh --level 3
```

### Run Against a Different Platform

```bash
./run-test-suite.sh --platform linux/amd64
```

This switches the harness's built-in validation image references to the matching amd64 manifests. If you override `--base-image` or `--vex-image`, make sure those image references match the requested platform.

### Generate Report

```bash
./run-test-suite.sh --output report.json
```

### Run With Custom Adapter

```bash
./run-test-suite.sh --adapter /path/to/your-adapter.sh
```

If your environment needs a custom Scout cache location:

```bash
DOCKER_SCOUT_CACHE_DIR=/tmp/dhi-scout-cache ./run-test-suite.sh
```

**Example Output**:
```json
{
  "scanner": "docker-scout-reference",
  "test_date": "2026-03-02T14:03:08Z",
  "results": {
    "level_1": {"passed": 4, "failed": 0},
    "level_2": {"passed": 3, "failed": 0},
    "level_3": {"passed": 3, "failed": 0},
    "level_4": {"passed": 5, "failed": 0}
  },
  "overall": "PASS",
  "certification_eligible": true
}
```

The script executes all listed tests. For Level 4, it builds deterministic fixture images because hardened base images intentionally include very few runtime tools.

### Keeping Validation Stable

The harness reduces drift by pinning core image references and using local generated VEX fixtures for matching logic checks.
It still relies on current vulnerability feeds to discover baseline CVEs/packages at runtime, so results can change as public data changes.

- **Gating interpretation**: prioritize integration behavior and investigate whether failures are behavior regressions vs feed drift.
- **Optional informational workflow**: run separate live-feed monitoring to track newly published vulnerabilities over time.

---

## Certification Requirements

To receive **DHI Scanner Certification**:

### Required
- ✅ Pass all Level 1 tests (Basic Integration)
- ✅ Pass all Level 2 tests (Package Routing)
- ✅ Pass at least 2/3 Level 3 tests (Derived Images)
- ✅ Document integration in public documentation
- ✅ Provide customer-facing DHI guidance

### Recommended
- ✅ Pass all Level 4 tests (Edge Cases)
- ✅ Support OCI 1.1 referrers
- ✅ Provide examples in documentation
- ✅ Participate in joint go-to-market

### Certification Benefits
- 🏆 "DHI Certified Scanner" badge
- 📢 Listed on Docker partner page
- 🤝 Joint marketing opportunities
- 🎯 Priority support from Docker

---

## Getting Help

### Test Failures

If you're failing tests, check:

1. **[FAQ](faq.md)** - Common issues and solutions
2. **[Troubleshooting Guide](troubleshooting.md)** - Debugging tips
3. **[Go Reference Implementation](../reference-implementations/go/)** - Working code

### Submit for Certification

When ready:

1. Run full test suite
2. Generate validation report
3. Submit the report through your standard partner engagement channel
4. Include:
   - Scanner name and version
   - Test results
   - Link to public documentation
   - Proposed announcement date

We'll review within 5 business days and provide certification or feedback.

---

## Next Steps

- 🌳 Study [Decision Trees](decision-trees.md)
- 💻 Try the [Go Reference Implementation](../reference-implementations/go/)
- 🧪 Test with [Example Images](../examples/)

**Questions?** Check the [FAQ](faq.md).
