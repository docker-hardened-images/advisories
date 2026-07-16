ARG SOURCE_IMAGE=dhi.io/bash:5-alpine3.24@sha256:e2b67997780c37dc8352fb3e1bae077497216767cd5edb25c710e3a0fef232ec
FROM ${SOURCE_IMAGE}

USER 0
RUN cp /etc/os-release /etc/os-release.before-dhi && \
    awk 'BEGIN { \
      print "NAME=\"Docker Hardened Images (Alpine)\""; \
      print "ID=dhi"; \
      print "ID_LIKE=alpine"; \
      print "VERSION_ID=3.24"; \
      print "PRETTY_NAME=\"Docker Hardened Images (Alpine 3.24)\""; \
    }' > /etc/os-release
