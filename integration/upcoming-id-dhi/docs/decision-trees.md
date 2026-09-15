# Decision Trees

## Image Model Detection

```mermaid
flowchart TD
  A[Read /etc/os-release] --> B{ID=dhi?}
  B -->|Yes| C[Use upcoming ID=dhi model]
  B -->|No| D{ID=alpine or ID=debian with DHI image evidence?}
  D -->|Yes| E[Use current-production DHI model]
  D -->|No| F[Use normal scanner model]
  C --> G[Use PURL type, ID_LIKE, and VERSION_ID to derive lineage and release]
  E --> H[Use current DHI detection and VEX overlay guide]
```

## Package Advisory Routing

```mermaid
flowchart TD
  A[Package from SBOM] --> B{PURL namespace}
  B -->|pkg:apk/dhi or pkg:deb/dhi| C{Image kind}
  B -->|pkg:apk/alpine or pkg:deb/debian| E[Normal upstream distro matching]
  B -->|other PURL type| F[Use normal scanner matching]
  C -->|Official DHI| M{Exact package and version in attached Docker-issued SBOM?}
  C -->|Derived DHI| N{DHI origin established?}
  M -->|No| J[Normalize to upstream Alpine or Debian package identity]
  M -->|Yes| D{PURL type}
  N -->|No| J
  N -->|Chain-ID/layer attribution or known base SBOM match| D
  J --> R[Use normal upstream matching with APK or dpkg version rules]
  D -->|apk| K[Resolve Alpine release from os_version or distro qualifier]
  D -->|deb| L[Resolve Debian release from os_version or distro qualifier]
  K --> G[Exact DHI Alpine release ecosystem, APK version rules]
  L --> H[Exact DHI Debian release ecosystem, dpkg version rules]
  G --> O{Exact version or affected range matches?}
  H --> O
  O -->|No| P[No matching vulnerability; no upstream fallback]
  O -->|Yes| I[Report DHI OSV finding]
  I --> Q[Published paired VEX is optional to consume]
```

## VEX Context

```mermaid
flowchart TD
  A[Finding matched from DHI OSV] --> B{Consume paired VEX context?}
  B -->|No| C[Report the OSV finding]
  B -->|Yes| D{Product PURL matches after canonicalization?}
  D -->|No| E[Report OSV finding and feed-integrity error]
  D -->|Yes| F{Status}
  F -->|affected| G[Report vulnerable with DHI status notes]
  F -->|under_investigation| H[Report under investigation with DHI status notes]
  F -->|not_affected or fixed| I[Report OSV/VEX state mismatch for generated data]
```

For an `under_investigation` assessment, generated DHI OSV lists the exact
package versions covered by the current assessment. The VEX branch labels an
existing OSV finding as unresolved; it does not create the finding.

## Mixed Production Cutover

```mermaid
flowchart LR
  A[Image family A still current-production] --> B[current-production guide]
  C[Image family B cut over to ID=dhi] --> D[upcoming-id-dhi guide]
  B --> E[Scanner report]
  D --> E
  F[Do not route by date alone] --> E
```
