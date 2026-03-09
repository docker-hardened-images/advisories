# Frequently Asked Questions

## General Questions

### What is Docker Hardened Images (DHI)?

DHI is Docker's enterprise-grade solution for container security. DHI images are:
- Built from source with SLSA Build Level 3 compliance
- Continuously maintained and patched
- Distroless (minimal attack surface)
- Verified with comprehensive provenance

### Why do I need to integrate my scanner with DHI?

Without proper integration, scanners report false positive and false negative CVEs on DHI images. This happens because:
1. DHI compiles packages from source with patches
2. DHI uses configuration that prevents exploitation
3. Traditional scanners don't understand DHI's security mitigations

Result: Customers see CVEs that don't actually apply, blocking DHI adoption.

### Is this integration required or optional?

**Strongly recommended** for accurate scanner results and customer trust. Without it:
- ❌ DHI customers see false positives and false negatives
- ❌ Scanner credibility suffers during audits and triage
- ❌ Support volume increases (reproducing and explaining CVEs)

---

## Technical Questions

### What is VEX?

VEX (Vulnerability Exploitability eXchange) is a standard for communicating vulnerability status:
- **Spec**: `https://openvex.dev/`

- **not_affected**: Vulnerability doesn't apply (false positive)
- **fixed**: DHI has patched this
- **affected**: Real vulnerability, not yet fixed
- **under_investigation**: DHI is evaluating

Think of VEX as a "status report card" for each CVE.

### What is the OSV feed?

OSV (Open Source Vulnerability) is a standard format for vulnerability data. DHI publishes an OSV feed containing CVEs for DHI-compiled packages (Python, Node, Go, etc.).

**Location**: `https://github.com/docker-hardened-images/advisories/tree/main/osv/`

### Why two feeds (OSV and VEX)?

**OSV Feed**: "What's actually vulnerable in DHI packages"
- Contains CVEs for `pkg:dhi/python`, `pkg:dhi/node`, etc.
- Authoritative source for DHI-compiled packages

**VEX Feed**: "Why certain CVEs don't apply"
- Explains false positives for any package included in a DHI
- Provides transparency on mitigations

### Can't you just provide one feed?

We could, but transparency is more valuable. With dual feeds:
- ✅ Customers see ALL CVEs
- ✅ VEX explains status and mitigations
- ✅ Auditors get complete picture
- ✅ Trust through transparency

### What does implementation scope look like?

**Basic Integration**:
- Image detection
- VEX loading and application
- Basic package routing

**Complete Integration**:
- OCI referrers support
- chainID-based derivation handling
- Full package routing logic
- Production optimizations

### Do we need to support OCI 1.1 referrers?

**Recommended but not required initially.**

**Option 1 (Simpler)**: Use comprehensive VEX feed from GitHub  
**Option 2 (Better)**: Use OCI referrers for image-specific SBOM/VEX

Most partners start with Option 1, add Option 2 later.

---

## Integration Questions

### Where do I start?

1. Review the [Decision Trees](decision-trees.md)
2. Run [Example Images](../examples/)
3. Test with [Validation Suite](../validation/)
4. Implement the [Go Reference Implementation](../reference-implementations/go/)

### What's the minimum viable integration?

**Level 1 (Basic)**:
- ✅ Detect DHI images via `/etc/os-release`
- ✅ Load comprehensive VEX feed
- ✅ Apply VEX to suppress false positives and record status/justification
- ✅ Route `pkg:dhi/*` to OSV feed

This gets you 80% of the value.

### How do I handle derived images?

**Key Concept**: Only apply DHI VEX to packages from the DHI base.

**Steps**:
1. Detect `com.docker.dhi.chain-id` label
2. Resolve the base layer boundary by matching the chainID against the layer chain
3. Retrieve SBOM via OCI referrers (attestation)
4. Associate SBOM packages to layers (base vs app layers)
5. Apply VEX only to packages from base layers; scan app layers normally

### What if I can't access GitHub feeds?

**Options**:
1. **Mirror feeds locally**: Clone repo, sync periodically
2. **Use OCI referrers**: VEX/SBOM travel with images

For enterprise deployments, we recommend option 2 (OCI referrers).

### How often do feeds update?

- **VEX**: Updated as DHI releases new images or mitigations
- **OSV**: Updated when new CVEs are discovered
- **Frequency**: Continuous (check for updates daily)

### What about air-gapped environments?

**OCI referrers are your solution:**
- SBOM and VEX are attached to images
- Travel with images through private registries
- No external feed access required

Attestations only come along automatically if the registry mirrors referrers; many do not yet.

---

## Package Routing Questions

### When do I use the OSV feed?

**Only for `pkg:dhi/*` packages:**
- `pkg:dhi/python@3.13.1` → Check OSV feed
- `pkg:dhi/node@22.0.0` → Check OSV feed
- `pkg:deb/debian/openssl@*` → **Don't** check OSV feed

**Rule**: If PURL type is `dhi`, use OSV exclusively.

### How do I know if a package is DHI-compiled?

**Check the PURL type:**
```
pkg:dhi/python      → DHI-compiled
pkg:deb/debian/*    → Upstream package
pkg:pypi/flask      → Application package
```

### What if OSV directory doesn't exist?

**No directory = no vulnerabilities, or no machine-readable advisories.**

Example:
```bash
$ curl https://.../osv/python/
# Returns: CVE-2024-12254.json, CVE-2025-0938.json

$ curl https://.../osv/binutils/
# Returns: 404 Not Found
```

For binutils, there are currently no active vulnerabilities in DHI's version. For some vendors,
the advisory data may not be available in OSV format, so a missing directory can also mean no
machine-readable advisories exist yet.

### Should I check upstream for `pkg:dhi/*` packages?

**No! Never check upstream for DHI packages.**

DHI packages are built from source and may have:
- Backported patches
- Custom security configurations
- Version numbers that don't match upstream

Only trust the OSV feed for `pkg:dhi/*`.

---

## VEX Application Questions

### When should I apply VEX?

**Apply VEX when:**
- ✅ Image is identified as DHI
- ✅ Package PURL matches VEX statement (any PURL type)
- ✅ Package is from DHI base (for derived images)

**Don't apply VEX when:**
- ❌ Not a DHI image
- ❌ Package added by customer
- ❌ PURL doesn't match exactly

### How do I match VEX to CVEs?

**VEX matching requires exact PURL match:**

```json
{
  "vulnerability": {"name": "CVE-2024-12254"},
  "products": [{"@id": "pkg:dhi/python@3.13.1"}]
}
```

**Matches**: `pkg:dhi/python@3.13.1`  
**Doesn't match**: `pkg:dhi/python@3.13.2` (version differs)

### What if VEX and CVE database conflict?

**Trust VEX for DHI images.**

Example:
- Debian CVE database: CVE-2024-XXXX is vulnerable
- DHI VEX: CVE-2024-XXXX is not_affected

For DHI images, apply VEX status. The VEX statement includes justification explaining why.

### Can customers create their own VEX?

Yes! If customers build on DHI and add VEX statements, scanners should:
1. Apply DHI VEX to base packages
2. Apply customer VEX to customer packages
3. Merge VEX statements appropriately

### Should I show suppressed CVEs in reports?

**Yes, for transparency:**

```json
{
  "cve": "CVE-2024-12254",
  "severity": "HIGH",
  "status": "not_affected",
  "vex_applied": true,
  "justification": "DHI configuration prevents exploitation"
}
```

Customers appreciate seeing what was evaluated and suppressed.

---

## Troubleshooting

### My scanner doesn't apply VEX

**Check**:
1. VEX loading: `curl <VEX_URL>` works?
2. PURL matching: Are PURLs identical?
3. VEX parsing: Status field recognized?

**Common issues**:
- PURL format mismatch (namespaces, qualifiers)
- Status field not parsed
- VEX applied to wrong packages

### VEX applies to customer packages

**Problem**: Derived image has customer packages getting DHI VEX.

**Cause**: Scanner not checking package origin.

**Fix**:
1. Detect chainID label
2. Identify base layer boundary (chainID match)
3. Map SBOM packages to layers
4. Apply VEX only to base packages

### Scanner reports different SBOM than expected

**Cause**: Scanner indexed filesystem instead of using attestation.

**Fix**:
1. Implement OCI referrers lookup
2. Fall back to `/opt/docker/sbom/.spdx.json`
3. Don't rely on package manager databases (DHI is distroless)

### OSV feed returns 404

**This is normal!**

No directory = no current vulnerabilities for that package.

Example: `pkg:dhi/bash` might have no known CVEs.

---

## Business Questions

### Is there a certification program?

**Yes!** Partners who pass our validation suite can get:
- ✅ "DHI Certified Scanner" badge
- ✅ Listed on Docker's partner page
- ✅ Joint go-to-market opportunities

See [Certification Requirements](../validation/certification.md).

### What's the partner benefit?

- Access to Docker's 50,000+ enterprise customers
- Competitive advantage in enterprise security programs
- Enhanced offering for mutual customers
- Joint marketing opportunities

### How long until we can announce integration?

**Timeline depends on integration level:**
- Basic (VEX + OSV): 2-4 weeks → Announce after validation
- Complete (chainID, OCI): 1-3 months → Announce at milestones

Current partners: Docker Scout, Trivy (CLI), Grype

### What support does Docker provide?

- 📖 Documentation (this repo)
- 💻 Reference implementations
- 🧪 Test data and validation tools
- 👥 Regular technical sync meetings
- 🎯 Joint go-to-market support

---

## Still Have Questions?

- 📖 **Read more**: [Decision Trees](decision-trees.md)
- 🧪 **Validate your implementation**: [Test Suite](../validation/test-suite.md)
