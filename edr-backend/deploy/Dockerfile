# deploy/Dockerfile
FROM golang:1.23-alpine AS builder
RUN apk add --no-cache gcc musl-dev git
WORKDIR /app
COPY go.mod ./
RUN go mod download || true
COPY . .
RUN go mod tidy && \
    CGO_ENABLED=0 go build -ldflags="-w -s" -o /edr-backend ./cmd/server

FROM alpine:3.19
RUN apk add --no-cache ca-certificates tzdata
COPY --from=builder /edr-backend /usr/local/bin/edr-backend
COPY config/ /app/config/
WORKDIR /app
EXPOSE 50051 8080
ENTRYPOINT ["/usr/local/bin/edr-backend", "--config", "/app/config/server.yaml"]
