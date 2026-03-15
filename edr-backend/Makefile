BINARY  = edr-backend
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")

.PHONY: all build run test clean docker-up docker-down

all: build

build:
	@echo "==> Building $(BINARY)..."
	go mod tidy
	CGO_ENABLED=0 go build -ldflags "-X main.Version=$(VERSION) -w -s" -o $(BINARY) ./cmd/server
	@echo "==> ./$(BINARY) ready"

run: build
	./$(BINARY) --config config/server.yaml

test:
	go test ./... -v -race -count=1

clean:
	rm -f $(BINARY)

# Docker targets
docker-up:
	docker compose -f deploy/docker-compose.yml up -d --build
	@echo "==> Backend:  http://localhost:8080"
	@echo "==> gRPC:     localhost:50051"
	@echo "==> Postgres: localhost:5432"

docker-down:
	docker compose -f deploy/docker-compose.yml down

docker-logs:
	docker compose -f deploy/docker-compose.yml logs -f backend

# Local postgres (without Docker)
db-start:
	@which pg_ctl >/dev/null || { echo "Install postgresql"; exit 1; }
	initdb -D /tmp/edr-db 2>/dev/null || true
	pg_ctl -D /tmp/edr-db -l /tmp/edr-db/pg.log start 2>/dev/null || true
	createdb edr 2>/dev/null || true
	createuser -s edr 2>/dev/null || true

help:
	@echo "Targets: build run test clean docker-up docker-down docker-logs db-start"

# Generate self-signed TLS certs for dev/testing.
# Puts files in deploy/certs/. Copy to /etc/edr/tls/ on the backend host.
# For agents: copy ca.crt and optionally issue per-agent client certs.
gen-certs:
	@echo "==> Generating self-signed CA + server cert in deploy/certs/"
	@mkdir -p deploy/certs
	@# 1. CA key + cert (10-year)
	openssl genrsa -out deploy/certs/ca.key 4096
	openssl req -new -x509 -days 3650 -key deploy/certs/ca.key \
		-subj "/CN=EDR-CA/O=TraceGuard" \
		-out deploy/certs/ca.crt
	@# 2. Server key + CSR
	openssl genrsa -out deploy/certs/server.key 2048
	openssl req -new -key deploy/certs/server.key \
		-subj "/CN=edr-backend/O=TraceGuard" \
		-out deploy/certs/server.csr
	@# 3. Sign server cert with CA; include localhost + 127.0.0.1 as SANs
	@echo "subjectAltName=DNS:localhost,DNS:edr-backend,IP:127.0.0.1" > /tmp/edr-san.ext
	openssl x509 -req -days 825 \
		-in deploy/certs/server.csr \
		-CA deploy/certs/ca.crt -CAkey deploy/certs/ca.key -CAcreateserial \
		-extfile /tmp/edr-san.ext \
		-out deploy/certs/server.crt
	@echo "==> Certs written to deploy/certs/"
	@echo "    ca.crt     — distribute to every agent"
	@echo "    server.crt — backend certificate"
	@echo "    server.key — backend private key (keep secret)"
	@echo "Next: copy to /etc/edr/tls/ and set server.tls.enabled: true"

