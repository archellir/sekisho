.PHONY: build run test clean docker deploy fmt vet generate-config

APP_NAME := sekisho
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")

LDFLAGS := -ldflags "-X main.Version=$(VERSION) -X main.BuildTime=$(BUILD_TIME) -X main.Commit=$(COMMIT)"

build:
	@echo "Building $(APP_NAME)..."
	CGO_ENABLED=0 go build $(LDFLAGS) -o bin/$(APP_NAME) ./cmd/proxy

build-all:
	@echo "Building for multiple platforms..."
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build $(LDFLAGS) -o bin/$(APP_NAME)-linux-amd64 ./cmd/proxy
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build $(LDFLAGS) -o bin/$(APP_NAME)-linux-arm64 ./cmd/proxy
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 go build $(LDFLAGS) -o bin/$(APP_NAME)-darwin-amd64 ./cmd/proxy
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build $(LDFLAGS) -o bin/$(APP_NAME)-darwin-arm64 ./cmd/proxy

run: build
	@echo "Running $(APP_NAME)..."
	./bin/$(APP_NAME) -config configs/config.yaml

run-dev:
	@echo "Running $(APP_NAME) in development mode..."
	go run ./cmd/proxy -config configs/config.yaml

test:
	@echo "Running tests..."
	go test -v ./...

test-race:
	@echo "Running tests with race detection..."
	go test -race -v ./...

test-cover:
	@echo "Running tests with coverage..."
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

bench:
	@echo "Running benchmarks..."
	go test -bench=. -benchmem ./...

fmt:
	@echo "Formatting code..."
	go fmt ./...

vet:
	@echo "Running go vet..."
	go vet ./...

lint:
	@echo "Running linter..."
	golangci-lint run

tidy:
	@echo "Tidying modules..."
	go mod tidy

clean:
	@echo "Cleaning up..."
	rm -rf bin/
	rm -f coverage.out coverage.html

generate-config:
	@echo "Generating default configuration..."
	./bin/$(APP_NAME) -generate-config > config-example.yaml

docker:
	@echo "Building Docker image..."
	docker build -t $(APP_NAME):$(VERSION) .
	docker tag $(APP_NAME):$(VERSION) $(APP_NAME):latest

docker-push:
	@echo "Pushing Docker image..."
	docker push $(APP_NAME):$(VERSION)
	docker push $(APP_NAME):latest

deploy-k8s:
	@echo "Deploying to Kubernetes..."
	kubectl apply -f deployments/k8s/sekisho.yaml

install:
	@echo "Installing $(APP_NAME)..."
	go install $(LDFLAGS) ./cmd/proxy

dev-setup:
	@echo "Setting up development environment..."
	go mod download
	@if ! command -v golangci-lint &> /dev/null; then \
		echo "Installing golangci-lint..."; \
		curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(shell go env GOPATH)/bin; \
	fi

help:
	@echo "Available targets:"
	@echo "  build          - Build the application"
	@echo "  build-all      - Build for multiple platforms"  
	@echo "  run            - Build and run the application"
	@echo "  run-dev        - Run in development mode"
	@echo "  test           - Run tests"
	@echo "  test-race      - Run tests with race detection"
	@echo "  test-cover     - Run tests with coverage report"
	@echo "  bench          - Run benchmarks"
	@echo "  fmt            - Format code"
	@echo "  vet            - Run go vet"
	@echo "  lint           - Run linter"
	@echo "  tidy           - Tidy go modules"
	@echo "  clean          - Clean build artifacts"
	@echo "  generate-config- Generate default config file"
	@echo "  docker         - Build Docker image"
	@echo "  docker-push    - Push Docker image"
	@echo "  deploy-k8s     - Deploy to Kubernetes"
	@echo "  install        - Install binary"
	@echo "  dev-setup      - Setup development environment"
	@echo "  help           - Show this help"