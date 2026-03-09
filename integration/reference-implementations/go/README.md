# Go Reference Implementation

This reference implementation demonstrates the core DHI integration flow using OCI registry APIs:

- Reads `/etc/os-release` from image layers (no container runtime required)
- Detects chainID and derived images by comparing the chainID to the layer chain
- Retrieves SBOM and VEX via OCI referrers (attestations)

## Requirements

- Go 1.25+
- Registry access to the image and its referrers

## Usage

```bash
cd reference-implementations/go
go run . --image dhi.io/bash:5
```

## What It Outputs

Output values are illustrative. On multi-arch images, this reference implementation selects the host platform, so chainID values and attestation predicate types can vary by machine architecture.

```
Image: dhi.io/bash:5
DHI: true
chainID label: sha256:...
chainID layer index: 4
Derived: false
SBOM attestation: https://cyclonedx.org/bom/v1.6
VEX attestation: https://openvex.dev/ns/v0.2.0
```

## Notes

- This is a reference implementation; production scanners should add caching, retries, and richer SBOM/VEX parsing.
- For derived images, use the chainID boundary to decide which packages are from the DHI base before applying VEX.

--- 

**Docker Hardened Images** - Building secure containers, together.
