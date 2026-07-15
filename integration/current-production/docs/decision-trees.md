# DHI Scanner Integration: Decision Trees

This document provides visual flowcharts to guide scanner integration logic.

## Table of Contents

1. [Master Scanning Flow](#master-scanning-flow)
2. [Data Gathering](#data-gathering)
3. [Package Classification](#package-classification)
4. [VEX Application](#vex-application)
5. [Quick Reference Matrix](#quick-reference-matrix)

---

## Master Scanning Flow

```mermaid
graph TD
    A[Start: Receive Image to Scan] --> B[Check /etc/os-release]
    B --> C{ID = alpine<br/>or debian?}
    C -->|No| D[Use Standard Scanner Logic]
    C -->|Yes| E{PRETTY_NAME contains<br/>'Docker Hardened Images'?}
    E -->|No| F[Regular Alpine/Debian Scanning]
    E -->|Yes| G[DHI Image Detected]
    G --> H{Check Labels:<br/>com.docker.dhi.chain-id?}
    H -->|Not Found| I[Pure DHI Image]
    H -->|Found| J{chainID matches<br/>last layer?}
    J -->|Yes| I
    J -->|No| K[Derived DHI Image]
    I --> L[Gather Required Data]
    K --> L
    L --> M[Classify Packages]
    M --> N[Match CVEs]
    N --> O[Apply VEX]
    O --> P[Generate Report]
```

---

## Data Gathering

### Step 1: SBOM Retrieval

```mermaid
graph TD
    A[Get Image SBOM] --> B{Which Method?}
    B -->|Preferred| C[OCI Referrers]
    B -->|Fallback| D[Generate from Filesystem]
    
    C --> C1[Resolve platform digest]
    C1 --> C2[List OCI referrers]
    C2 --> C3[Find SPDX or CycloneDX predicate]
    C3 --> C4[Download SBOM attestation]
    
    D --> D1[Scan filesystem]
    D1 --> D2[Index packages]
    D2 --> D3[Include /opt/docker/sbom/ snippets]
    
    C4 --> E[Complete SBOM with PURLs]
    D3 --> E
```

### Step 2: VEX Retrieval

```mermaid
graph TD
    A[Get VEX Statements] --> B[Option 1: Comprehensive VEX]
    A --> C[Option 2: OCI Referrers]
    
    B --> B1[Fetch from GitHub:<br/>dhi.vex.json]
    
    C --> C1[Same as SBOM process]
    C1 --> C2[Find OpenVEX predicate]
    
    B1 --> D[VEX Statements Ready]
    C2 --> D
```

### Step 3: OSV Feed Access

```mermaid
graph TD
    A[Get OSV Advisory Data] --> B[Clone/Poll GitHub Repository]
    B --> C[github.com/docker-hardened-images/<br/>advisories/osv/]
    C --> D[Browse by package name]
    D --> E{Package directory<br/>exists?}
    E -->|Yes| F[CVE JSON files available]
    E -->|No| G[No active vulnerabilities<br/>for this package]
    
    style G fill:#90EE90
```

---

## Package Classification

```mermaid
graph TD
    A[For Each Package in SBOM] --> B[Parse Package PURL]
    B --> C{PURL Type?}
    
    C -->|pkg:dhi/*| D[Route 1: DHI-Compiled Package]
    C -->|pkg:deb/*<br/>pkg:apk/*| E[Route 2: Distro Package]
    C -->|pkg:pypi/*<br/>pkg:npm/*<br/>etc.| F[Route 3: Application Package]
    
    D --> D1[Match Against OSV Feed EXCLUSIVELY]
    D1 --> D2{OSV directory<br/>exists?}
    D2 -->|No| D3[NO VULNERABILITIES]
    D2 -->|Yes| D4[Load CVEs from OSV]
    D4 --> D5[Do NOT check upstream databases]
    
    E --> E0[Also Consider DHI OSV<br/>for DHI image scans]
    E0 --> E1[Match Against Upstream CVE DB]
    E1 --> E2[Debian Security Tracker<br/>or Alpine Security]
    E2 --> E3[Get all CVEs]
    E3 --> E4[Then Check VEX for 'not_affected']
    E4 --> E5[Apply VEX Status]
    
    F --> F0[Also Consider DHI OSV<br/>for DHI image scans]
    F0 --> F1[Use Standard Scanner Logic]
    F1 --> F2[Query appropriate upstream<br/>PyPI, npm, RubyGems, etc.]
    F2 --> F3[Check GitHub Advisories]
    F3 --> F4[Then Check VEX for matching PURLs<br/>if package is from DHI base]
    
    D3 --> G[Package Assessment Complete]
    D5 --> G
    E5 --> G
    F4 --> G
    
    style D3 fill:#90EE90
```

---

## VEX Application

### Critical: VEX Matching Logic

```mermaid
graph TD
    A[For Each CVE Found] --> B{Is this a<br/>DHI image?}
    B -->|No| C[No VEX Processing<br/>Report CVE]
    B -->|Yes| D{chainID<br/>present?}
    
    D -->|No| E[Pure DHI Image]
    D -->|Yes| F[Derived DHI Image]
    
    E --> G[Apply VEX Directly]
    F --> H[Extra Validation Required]
    
    G --> I[Find VEX Statements Where:]
    H --> I
    
    I --> I1[1. vulnerability.name = CVE-ID]
    I1 --> I2["2. products[].@id matches PURL"]
    
    I2 --> J{VEX Found?}
    J -->|No| K[No VEX for this CVE<br/>Report as Vulnerable]
    J -->|Yes| L{For Derived Images:<br/>Is package in DHI base?}
    
    L --> L1[Method A: Base SBOM via referrers]
    L --> L2[Method B: Check Layer Origin]
    
    L1 --> M{Package PURL+version<br/>in base SBOM?}
    L2 --> M
    
    M -->|No| N[Customer-Added Package<br/>DO NOT Apply VEX<br/>Report CVE Normally]
    M -->|Yes| O[Check VEX Status]
    
    O --> P{Status?}
    P -->|not_affected| Q[Suppress CVE<br/>Mark as False Positive<br/>Include VEX Justification]
    P -->|fixed| R[Suppress CVE<br/>Mark as Patched<br/>Include VEX Notes]
    P -->|affected or<br/>under_investigation| S[Report CVE<br/>Include VEX Status Notes]
    
    style Q fill:#90EE90
    style R fill:#90EE90
    style N fill:#FFB6C6
    style S fill:#FFD700
```

### Derived Image: Package Origin Check

```mermaid
graph TD
    A[Derived Image: Need to Validate Package Origin] --> B{Which Method?}
    
    B -->|Method A: SBOM Comparison| C[Fetch DHI Base SBOM]
    C --> C1[Use chainID to identify base boundary]
    C1 --> C2[Compare: Package in base?]
    C2 --> C3{PURL + Version<br/>match exactly?}
    C3 -->|Yes| D[From DHI Base<br/>Apply VEX]
    C3 -->|No| E[Customer Modified<br/>No VEX]
    
    B -->|Method B: Layer Analysis| F[Analyze Image Layers]
    F --> F1[Identify DHI base layers<br/>vs customer layers]
    F1 --> F2{Package from<br/>DHI layer?}
    F2 -->|Yes| D
    F2 -->|No| E
    
    B -->|Method C: Checksum| G[Compare Package Checksums]
    G --> G1[Get checksum from DHI SBOM]
    G1 --> G2{Checksums<br/>match?}
    G2 -->|Yes| D
    G2 -->|No| E
    
    style D fill:#90EE90
    style E fill:#FFB6C6
```

---

## Quick Reference Matrix

### Package Routing Decision Table

| Package PURL Pattern | Advisory Source | VEX Source | Apply VEX? | Notes |
|---------------------|----------------|------------|-----------|-------|
| `pkg:dhi/python@*` | DHI OSV **ONLY** | DHI VEX | ✅ Always | Never check upstream |
| `pkg:dhi/node@*` | DHI OSV **ONLY** | DHI VEX | ✅ Always | Never check upstream |
| `pkg:deb/debian/openssl@*` | DHI OSV + Debian Security Tracker | DHI VEX | ✅ For DHI images | Upstream + DHI OSV + VEX overlay |
| `pkg:apk/alpine/musl@*` | DHI OSV + Alpine Security | DHI VEX | ✅ For DHI images | Upstream + DHI OSV + VEX overlay |
| `pkg:pypi/flask@*` (customer) | DHI OSV + PyPI, GitHub | DHI VEX (if in base SBOM) | ✅ If from DHI base | DHI scans include OSV consideration for all packages |
| `pkg:npm/express@*` (customer) | DHI OSV + npm, GitHub | DHI VEX (if in base SBOM) | ✅ If from DHI base | DHI scans include OSV consideration for all packages |

### VEX Status Actions

| VEX Status | Scanner Action | User Display | Include in Report? |
|-----------|---------------|--------------|-------------------|
| `not_affected` | Suppress CVE | False Positive | ✅ Yes (with justification) |
| `fixed` | Suppress CVE | Patched | ✅ Yes (with fix details) |
| `affected` | Report CVE | Vulnerable | ✅ Yes (with VEX notes) |
| `under_investigation` | Report CVE | Under Review | ✅ Yes (with status) |

### Image Type Detection

| Condition | Image Type | VEX Strategy |
|-----------|-----------|--------------|
| `/etc/os-release` ID=alpine/debian + PRETTY_NAME contains "Docker Hardened Images" + No chainID | Pure DHI | Direct VEX application |
| Same as above + chainID label present | Derived DHI | Validate package origin before VEX |
| `/etc/os-release` ID=alpine/debian + No "Docker Hardened Images" | Regular distro | No DHI VEX |

---

## Common Failure Modes

### ❌ Anti-Pattern: Naive VEX Application

```mermaid
graph TD
    A[Scanner Detects chainID] --> B[Applies ALL DHI VEX to Entire Image]
    B --> C[Result: Misses customer-added vulnerabilities]
    
    style C fill:#FF6B6B
```

**Problem**: Customer adds vulnerable `pkg:pypi/flask@2.0.0`, scanner incorrectly applies DHI VEX and suppresses the real vulnerability.

### ✅ Correct Pattern: Package-Specific VEX

```mermaid
graph TD
    A[Scanner Detects chainID] --> B[Fetches DHI Base SBOM]
    B --> C[Compares Package Lists]
    C --> D{Package in<br/>DHI base?}
    D -->|Yes| E[Apply VEX for this package]
    D -->|No| F[Scan normally, no VEX]
    
    style E fill:#90EE90
    style F fill:#90EE90
```

**Solution**: VEX only applies to packages that exist unmodified from DHI base.

---

## Testing Your Logic

Use these test cases to validate your decision tree implementation:

1. **Pure DHI Image**: `dhi.io/python:3.13-alpine3.23@sha256:8061e30b8cfbf285c50a760486983eaec1e91925d3dc3fc1b801e5a40dfbbc51`
   - Should apply VEX to all `pkg:dhi/*` and `pkg:deb/*` packages
   
2. **Derived with Customer Packages**:
   ```dockerfile
   FROM dhi.io/python:3.13-alpine3.23@sha256:8061e30b8cfbf285c50a760486983eaec1e91925d3dc3fc1b801e5a40dfbbc51
   RUN pip install flask==2.0.0  # Has known CVE
   ```
   - Should apply VEX to DHI packages
   - Should report CVE in flask (no VEX)

3. **Multi-stage (No DHI in Final)**:
   ```dockerfile
   FROM dhi.io/python:3.13-alpine3.23@sha256:8061e30b8cfbf285c50a760486983eaec1e91925d3dc3fc1b801e5a40dfbbc51 AS builder
   FROM ubuntu:22.04
   COPY --from=builder /app /app
   ```
   - Should not apply any DHI VEX (no DHI packages in final image)

4. **Modified DHI Package**:
   - Customer replaces `pkg:dhi/python@3.13` with custom build
   - PURL changes, VEX won't match → correct behavior

---

## Next Steps

- 🧪 Test with [Example Images](../examples/)
- ✅ Validate with [Test Suite](../validation/test-suite.md)
- 💻 Review the [Go Reference Implementation](../reference-implementations/go/)

---

**Questions?** Check the [FAQ](faq.md).
