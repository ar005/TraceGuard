# deploy/Dockerfile
# Binary is pre-built on the host (make build) and copied in.
# This avoids pulling golang builder images and keeps the image tiny.
FROM alpine:3.19@sha256:6baf43584bcb78f2e5847d1de515f23499913ac9f12bdf834811a3145eb11ca1
RUN apk add --no-cache ca-certificates tzdata
COPY edr-backend /usr/local/bin/edr-backend
COPY config/ /app/config/
WORKDIR /app
EXPOSE 50051 8080
ENTRYPOINT ["/usr/local/bin/edr-backend", "--config", "/app/config/server.yaml"]
