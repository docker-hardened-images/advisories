<img alt="dhi-banner" src="https://github.com/user-attachments/assets/fc0ca203-3f25-4ae5-aa8e-e3918bbcc31f" />

# Docker Hardened Images - Scanner Integration Guide

Documentation and reference implementations for integrating third-party
security scanners with Docker Hardened Images (DHI). This page explains how the
current production scanner model and the upcoming `/etc/os-release` `ID=dhi`
model coexist during the migration.

> **Work in progress:** The cutover will happen gradually, image by image, not
> as a single global switch. Both models will remain live during the rollout.
> Docker will not publish a cutover image with `ID=dhi` until generated
> advisory data is available for that image and its contents.

Start with the [one-page overview](dhi-scanner-integration-upcoming-changes.md)
for a concise summary of the upcoming scanner integration changes, then use the
model-specific guides below for implementation details.

## Which Guide Should I Read?

| Guide | When to use it | Advisory model |
| --- | --- | --- |
| [current-production](current-production/README.md) | For images and advisory artifacts that are live before the `ID=dhi` cutover. | DHI images still identify as `ID=alpine` or `ID=debian`; scanners need DHI-specific detection and VEX overlay behavior. |
| [upcoming-id-dhi](upcoming-id-dhi/README.md) | For images that identify with `/etc/os-release` `ID=dhi`. | DHI OS packages use `pkg:(apk\|deb)/dhi/...` package identity and generated DHI OSV determines whether a finding exists. |

The guides intentionally coexist during the migration. Scanner integrations
should route by the image model they actually observe, not by an assumed global
cutover date. See [migration notes](migration/README.md) for production
reference anchors used by the examples in this guide.

The model-specific guides define the integration contract. The one-page
overview is explanatory and should not be used as a separate routing contract.

## New Model Summary

Cutover images use:

```text
ID=dhi
ID_LIKE=alpine|debian
VERSION_ID=<upstream distro version>
```

For OS packages in the DHI base layer, SBOM package PURLs use the DHI namespace:

```text
pkg:apk/dhi/<package>@<apk-version>...
pkg:deb/dhi/<package>@<deb-version>...
```

`ID_LIKE` still identifies the underlying package manager family for version
comparison, but it is not the advisory namespace for DHI-owned OS packages.

## Migration Stages

| Stage | Image state | Advisory state | Scanner expectation |
| --- | --- | --- | --- |
| Before first cutover | All production images use the current-production model. | Existing advisories repo artifacts remain live. | Use the current-production guide. Upcoming examples are local-only fixtures. |
| First family cutover | One or more published image families report `ID=dhi`. Publication of that cutover image is the readiness signal. | Generated DHI advisory data is already available for the image and its contents. | For official images, match packages against the Docker-issued OCI-referrer SBOM attached to the resolved platform digest. For derived images, establish DHI origin through chain-ID/layer attribution or a known base's Docker-issued SBOM. Route packages not attributed to DHI through normal upstream Alpine or Debian coverage. For an eligible DHI package, no matching affected range means no matching vulnerability. Keep current-production handling for non-cutover families. |
| Mixed production | Both models are live. | Each published `ID=dhi` image has corresponding generated advisory data; existing advisory artifacts remain live for non-cutover images. | Detect per image and per package, and retain the corresponding product-membership check for DHI advisory routing. Do not assume all DHI images have moved. |
| Completed cutover | DHI base layers consistently report `ID=dhi`. | Generated DHI OSV and VEX data is the normal advisory surface. | Retire current-production-only detection and VEX overlay assumptions. |

## Resources

- [One-page overview: DHI scanner integration upcoming changes](dhi-scanner-integration-upcoming-changes.md)
- [Current production guide](current-production/README.md)
- [Upcoming `ID=dhi` guide](upcoming-id-dhi/README.md)
- [OpenVEX Spec](https://openvex.dev/)
- [OCI Referrers](https://github.com/opencontainers/distribution-spec/blob/main/spec.md#listing-referrers)
