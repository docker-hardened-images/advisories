<img alt="dhi-banner" src="https://github.com/user-attachments/assets/fc0ca203-3f25-4ae5-aa8e-e3918bbcc31f" />

# Docker Hardened Images - Scanner Integration Guide

This page explains the current production model for integrating third-party
security scanners with Docker Hardened Images (DHI).

> Migration note: this directory describes the current production model before
> the `/etc/os-release` `ID=dhi` cutover. The upcoming model is documented in
> [`../upcoming-id-dhi`](../upcoming-id-dhi/README.md).

## 🎯 Quick Start

1. Review the [Decision Trees](docs/decision-trees.md)
2. Read the DHI docs to explore or get real images:
   - [Explore DHI images](https://docs.docker.com/dhi/how-to/explore/)
   - [Mirror DHI images](https://docs.docker.com/dhi/how-to/mirror/)
3. Run the [Go Reference Implementation](reference-implementations/go/)
4. Try the [Example Images](examples/)
5. Validate using the [Test Suite](validation/test-suite.md)

## 🚀 Reference Implementation

- **Go**: `reference-implementations/go/`

## 📄 Resources

- **Integration FAQ**: [docs/faq.md](docs/faq.md)
- **OSV Feed**: `https://github.com/docker-hardened-images/advisories/tree/main/osv/`
- **VEX by image repository**: `https://github.com/docker-hardened-images/advisories/tree/main/vex/`
- **VEX by package**: `https://github.com/docker-hardened-images/advisories/blob/main/index.json`
- **OpenVEX Spec**: `https://openvex.dev/`
- **OCI Referrers**: `https://github.com/opencontainers/distribution-spec/blob/main/spec.md#listing-referrers`

## VEX Sources

Scanner integrations can sync `index.json` and the referenced documents under
`pkg/` for package-oriented VEX discovery.

The repository also provides other views and distribution paths:

- `vex/<image-repository>/dhi-<image-repository>.vex.json` is organized by DHI
  image repository. It is not tied to one image tag or digest.
- OCI referrers provide VEX and SBOM attestations attached to an image digest.

Use the scanned image's package inventory or SBOM to determine which VEX
products apply.

---

**Docker Hardened Images** - Building secure containers, together.
