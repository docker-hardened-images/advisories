# DHI Advisory Migration Notes

This page records production reference anchors used by the scanner integration
examples. For the authoritative migration routing table, see
[`../README.md`](../README.md#migration-stages).

The migration has two live models for a period of time:

1. Current production images continue to use upstream OS identity in
   `/etc/os-release`.
2. New cutover images use `ID=dhi` with `ID_LIKE=alpine` or `ID_LIKE=debian`.

During that overlap, scanner integrations need to route by the image model they
actually observe, not by an assumed global cutover date.

## Production Detail Anchors

The upcoming guide references production image families and advisory examples,
but the `ID=dhi` end-to-end examples remain synthetic until generated DHI
artifacts exist in production.

Current examples used while developing the migration:

| Purpose | Reference |
| --- | --- |
| Alpine scanner spot-check | `dhi.io/bash:5-alpine3.24` |
| Current production Python guide image | `dhi.io/python:3.13-alpine3.23@sha256:219ee56599402640c694fd41fce8b009b6abcfc63e05d74239010024af94e9be` |
| Current production VEX image | `dhi.io/bash:5@sha256:55ca1da07f8332342db5224144e7455d68a2864645f1c1b7ee5f1324f11cce84` |
| Debian production reference from definitions | `dhi/bash:5.2.37-debian13@sha256:d34ec6dfa8a2faf4eb59f09452b9b133f29b9e785d304730bce00963e7dcd3c5` |
