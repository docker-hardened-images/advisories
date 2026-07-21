FROM alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b AS upstream

RUN apk add --no-cache jq && \
    awk 'BEGIN { RS = ""; ORS = "\n\n" } /(^|\n)P:jq\n/ { print }' \
      /lib/apk/db/installed > /tmp/customer-packages-jq

FROM dhi.io/bash:5-alpine3.24@sha256:e2b67997780c37dc8352fb3e1bae077497216767cd5edb25c710e3a0fef232ec

USER 0
RUN cp /etc/os-release /etc/os-release.before-dhi && \
    awk 'BEGIN { \
      print "NAME=\"Docker Hardened Images (Alpine)\""; \
      print "ID=dhi"; \
      print "ID_LIKE=alpine"; \
      print "VERSION_ID=3.24"; \
      print "PRETTY_NAME=\"Docker Hardened Images (Alpine 3.24)\""; \
    }' > /etc/os-release

COPY --from=upstream /tmp/customer-packages-jq /tmp/customer-packages-jq
COPY --from=upstream /usr/bin/jq /usr/bin/jq
RUN awk '1' /tmp/customer-packages-jq >> /lib/apk/db/installed
