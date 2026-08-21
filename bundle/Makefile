VERSION ?= dev
LDFLAGS := -X main.version=$(VERSION)

.PHONY: help build test fmt vet lint clean
help: ## List targets.
	@grep -hE '^[a-z-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  %-10s %s\n",$$1,$$2}'

build: ## Build the CLI into bin/.
	go build -ldflags "$(LDFLAGS)" -o bin/tessera-bundle ./cmd/tessera-bundle

test: fmt vet ## Run the suite with the race detector.
	go test -race ./...

fmt: ## Format the source.
	gofmt -l -w .

vet: ## Run go vet.
	go vet ./...

clean: ## Remove build output.
	rm -rf bin
