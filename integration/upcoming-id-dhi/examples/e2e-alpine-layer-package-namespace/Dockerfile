FROM alpine:3.24 AS upstream

RUN apk add --no-cache jq && \
    awk 'BEGIN { RS = ""; ORS = "\n\n" } /(^|\n)P:jq\n/ { print }' \
      /lib/apk/db/installed > /tmp/customer-packages-jq

FROM dhi.io/bash:5-alpine3.24

USER 0
COPY --from=upstream /tmp/customer-packages-jq /tmp/customer-packages-jq
COPY --from=upstream /usr/bin/jq /usr/bin/jq
RUN awk '1' /tmp/customer-packages-jq >> /lib/apk/db/installed && \
    cp /etc/os-release /etc/os-release.before-dhi && \
    awk 'BEGIN { \
      print "NAME=\"Docker Hardened Images (Alpine)\""; \
      print "ID=dhi"; \
      print "ID_LIKE=alpine"; \
      print "VERSION_ID=3.24"; \
      print "PRETTY_NAME=\"Docker Hardened Images (Alpine) 3.24\""; \
    }' > /etc/os-release
