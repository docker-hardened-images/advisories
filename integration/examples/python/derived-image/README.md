# Test Case: Derived DHI Python Image

This example tests VEX application when customers add packages on top of DHI images.

## What This Tests

- Detection of derived images via `com.docker.dhi.chain-id`
- Distinguishing DHI base packages from customer packages
- Applying VEX only to DHI packages
- Normal scanning for customer-added packages

## The Image

```dockerfile
FROM dhi.io/python:3.13-alpine3.23-dev@sha256:dc755b8ac42aca1c64b6083374c217f0a569ae58c7909297f8052ee60839e4f6 AS builder

COPY requirements.txt .
RUN python -m pip install --no-cache-dir --prefix /tmp/install -r requirements.txt

# requirements.txt:
# flask==2.3.0
# requests==2.31.0

FROM dhi.io/python:3.13-alpine3.23@sha256:8061e30b8cfbf285c50a760486983eaec1e91925d3dc3fc1b801e5a40dfbbc51 AS runtime
COPY --from=builder /tmp/install /opt/python
COPY app.py .
CMD ["python", "app.py"]
```

**Base**: `dhi.io/python:3.13-alpine3.23@sha256:8061e30b8cfbf285c50a760486983eaec1e91925d3dc3fc1b801e5a40dfbbc51`
**Type**: Derived (customer modifications)
**Customer packages**: Flask, Requests (via pip)

## The Challenge

This image mixes:
- **DHI packages**: `pkg:dhi/python@3.13.1`, Alpine system packages
- **Customer packages**: `pkg:pypi/flask@2.3.0`, `pkg:pypi/requests@2.31.0`

**Critical**: VEX should only apply to DHI base packages, not customer additions.

## Expected Scanner Behavior

### 1. Detect Derived Image

Check for chainID label:
```bash
docker inspect test-derived-python | grep com.docker.dhi.chain-id
```

Should return: `"com.docker.dhi.chain-id": "sha256:ad3d5af2..."`

### 2. Compare SBOMs

**Derived image SBOM** (what scanner sees):
- `pkg:dhi/python@3.13.1` ← From DHI
- `pkg:apk/alpine/musl@1.2.5-r0` ← From DHI
- `pkg:pypi/flask@2.3.0` ← Customer added
- `pkg:pypi/requests@2.31.0` ← Customer added

**Base image SBOM** (fetch via OCI referrers, using the chainID to identify base layers):
- `pkg:dhi/python@3.13.1`
- `pkg:apk/alpine/musl@1.2.5-r0`
- ... other DHI packages

### 3. Apply VEX Selectively

| Package | Origin | Apply VEX? | Scan Normally? |
|---------|--------|-----------|---------------|
| python@3.13.1 | DHI base | ✅ Yes | No |
| musl@1.2.5-r0 | DHI base | ✅ Yes | No |
| flask@2.3.0 | Customer | ❌ No | ✅ Yes |
| requests@2.31.0 | Customer | ❌ No | ✅ Yes |

## Expected Results

**DHI python package**:
- CVEs reported from DHI OSV feed
- VEX applied → False positives suppressed

**Customer Flask package**:
- CVEs reported from standard databases (PyPI, NVD)
- NO VEX applied → Real vulnerabilities show

Example expected output:
```
pkg:dhi/python@3.13.1
  ✅ CVE-2024-12254: not_affected (VEX applied)

pkg:pypi/flask@2.3.0
  ❌ CVE-2023-30861: HIGH (Real vulnerability, needs fixing)
```

## Run This Test

```bash
cd examples/python/derived-image
docker build -t test-derived-python .
docker run --rm test-derived-python
```

Your scanner should:
1. Detect chainID
2. Fetch base SBOM
3. Apply VEX only to base packages
4. Report Flask CVEs normally

## Troubleshooting

**Problem**: VEX applied to Flask package
**Fix**: Check SBOM comparison logic - only match packages present in base SBOM

**Problem**: VEX not applied to python package
**Fix**: Ensure chainID is detected and base SBOM is fetched

**Problem**: Can't fetch base SBOM
**Fix**: Use OCI referrers for the base image SBOM or map SBOM packages to layers and compare against the chainID boundary (see [Decision Trees](../../docs/decision-trees.md))

## Next Steps

- ✅ Understand derivation? Check [FAQ](../../docs/faq.md)
- 📖 See [Decision Trees](../../docs/decision-trees.md) for detailed flow

--- 

**Docker Hardened Images** - Building secure containers, together.
