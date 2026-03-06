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
