# Tessera Studio — local interface over the tessera analyser.

VERSION ?= dev
LDFLAGS := -X main.version=$(VERSION)

.PHONY: help
help: ## List targets.
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

.PHONY: build
build: ## Build the studio binary into bin/.
	go build -ldflags "$(LDFLAGS)" -o bin/tessera-studio ./cmd/tessera-studio

.PHONY: run
run: ## Serve a models directory (make run DIR=/path/to/models).
	go run ./cmd/tessera-studio $(DIR)

.PHONY: test
test: fmt vet ## Run the tests.
	go test ./... -race

.PHONY: fmt
fmt: ## Format the source.
	gofmt -w .

.PHONY: vet
vet: ## Run go vet.
	go vet ./...

.PHONY: clean
clean: ## Remove build output.
	rm -rf bin
