<img alt="dhi-banner" src="https://github.com/user-attachments/assets/fc0ca203-3f25-4ae5-aa8e-e3918bbcc31f" />

# Docker Hardened Images - Scanner Integration Guide

Documentation and reference implementations for integrating third-party security scanners with Docker Hardened Images (DHI). This repository serves as a guide for scanner vendors and teams looking to support DHI in their vulnerability scanning workflows.

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
- **VEX Feed**: `https://github.com/docker-hardened-images/advisories/tree/main/vex/`
- **OpenVEX Spec**: `https://openvex.dev/`
- **OCI Referrers**: `https://github.com/opencontainers/distribution-spec/blob/main/spec.md#listing-referrers`

--- 

**Docker Hardened Images** - Building secure containers, together.
