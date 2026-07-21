ARG SOURCE_IMAGE=dhi/bash:5.2.37-debian13@sha256:d34ec6dfa8a2faf4eb59f09452b9b133f29b9e785d304730bce00963e7dcd3c5
FROM ${SOURCE_IMAGE}

USER 0
RUN cp /etc/os-release /etc/os-release.before-dhi && \
    printf '%s\n' \
      'NAME="Docker Hardened Images (Debian)"' \
      'ID=dhi' \
      'ID_LIKE=debian' \
      'VERSION_ID=13' \
      'PRETTY_NAME="Docker Hardened Images (Debian 13)"' \
      > /etc/os-release
