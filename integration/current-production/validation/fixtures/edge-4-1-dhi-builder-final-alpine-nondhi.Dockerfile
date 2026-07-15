ARG BASE_IMAGE
FROM ${BASE_IMAGE} AS dhi_builder
RUN ["python", "-c", "open('/tmp/marker.txt','w').write('edge-4-1')"]

FROM alpine:3.21
COPY --from=dhi_builder /tmp/marker.txt /app/marker.txt
CMD ["cat", "/app/marker.txt"]
