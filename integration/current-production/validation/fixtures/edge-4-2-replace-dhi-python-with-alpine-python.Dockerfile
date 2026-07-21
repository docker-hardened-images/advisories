ARG BASE_IMAGE
FROM alpine:3.23 AS alpine_python_source
RUN apk add --no-cache python3 py3-pip

FROM ${BASE_IMAGE}
USER 0
# Remove DHI Python files and package SBOM metadata before overlaying Alpine Python.
RUN ["python", "-c", "import os,shutil; paths=['/opt/python','/opt/python-3.13.11','/opt/docker/sbom/dhi-pkg-python','/opt/docker/sbom/dhi-python','/opt/docker/sbom/python'];\nfor p in paths:\n  if os.path.islink(p):\n    os.unlink(p)\n  elif os.path.isdir(p):\n    shutil.rmtree(p, ignore_errors=True)\n  elif os.path.exists(p):\n    os.remove(p)"]
COPY --from=alpine_python_source /lib/apk /lib/apk
COPY --from=alpine_python_source /etc/apk /etc/apk
COPY --from=alpine_python_source /usr/bin/python3 /usr/bin/python3
COPY --from=alpine_python_source /usr/lib/python3.12 /usr/lib/python3.12
COPY --from=alpine_python_source /usr/lib/libpython3.12.so.1.0 /usr/lib/libpython3.12.so.1.0
USER 65532
CMD ["python3", "--version"]
