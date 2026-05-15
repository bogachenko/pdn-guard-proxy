APP_NAME := pdn-guard-proxy
GO_CMD := go
GO_MAIN := ./cmd/proxy
BIN_DIR := bin
BIN_PATH := $(BIN_DIR)/$(APP_NAME)

LISTEN_ADDR ?= :8080
TARGET_BASE_URL ?= http://127.0.0.1:9000
NATASHA_BASE_URL ?= http://127.0.0.1:8010
REQUEST_TIMEOUT_SECONDS ?= 15
MAX_BODY_BYTES ?= 262144

.PHONY: help
help:
	@echo "Available commands:"
	@echo "  make run              Run Go proxy locally"
	@echo "  make build            Build Go binary"
	@echo "  make test             Run Go tests"
	@echo "  make tidy             Run go mod tidy"
	@echo "  make fmt              Format Go code"
	@echo "  make vet              Run go vet"
	@echo "  make check            Run fmt, vet and test"
	@echo "  make docker-up        Start Natasha detector"
	@echo "  make docker-down      Stop Natasha detector"
	@echo "  make docker-build     Rebuild Natasha detector"
	@echo "  make clean            Remove build artifacts"
	@echo "  make health           Check Natasha detector health"
	@echo "  make test-block       Send request that must be blocked"
	@echo "  make test-forward     Send request that must be forwarded"

.PHONY: run
run:
	LISTEN_ADDR="$(LISTEN_ADDR)" \
	TARGET_BASE_URL="$(TARGET_BASE_URL)" \
	NATASHA_BASE_URL="$(NATASHA_BASE_URL)" \
	REQUEST_TIMEOUT_SECONDS="$(REQUEST_TIMEOUT_SECONDS)" \
	MAX_BODY_BYTES="$(MAX_BODY_BYTES)" \
	$(GO_CMD) run $(GO_MAIN)

.PHONY: build
build:
	mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 $(GO_CMD) build -trimpath -ldflags="-s -w" -o $(BIN_PATH) $(GO_MAIN)

.PHONY: test
test:
	$(GO_CMD) test ./...

.PHONY: tidy
tidy:
	$(GO_CMD) mod tidy

.PHONY: fmt
fmt:
	$(GO_CMD) fmt ./...

.PHONY: vet
vet:
	$(GO_CMD) vet ./...

.PHONY: check
check: fmt vet test

.PHONY: docker-up
docker-up:
	docker compose -f pdn-ner/docker-compose.yml up -d

.PHONY: docker-down
docker-down:
	docker compose -f pdn-ner/docker-compose.yml down

.PHONY: docker-build
docker-build:
	docker compose -f pdn-ner/docker-compose.yml up -d --build

.PHONY: clean
clean:
	rm -rf $(BIN_DIR)

.PHONY: health
health:
	curl -i http://127.0.0.1:8010/health

.PHONY: test-block
test-block-1:
	curl -i http://127.0.0.1:8080/test \
		-H "Content-Type: application/json" \
		-d '{"message":"Позвони Ивану Петрову"}'

test-block-2:
	curl -i http://127.0.0.1:8080/test \
		-H "Content-Type: application/json" \
		-d '{"message":"Вот номер +7 999 123-45-67"}'

.PHONY: test-forward
test-forward:
	curl -i http://127.0.0.1:8080/test \
		-H "Content-Type: application/json" \
		-d '{"message":"Дай цена по всем"}'