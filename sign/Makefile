# Tessera Sign — hybrid post-quantum signatures for bills of materials.

VERSION ?= dev
LDFLAGS := -X main.version=$(VERSION)

.PHONY: help
help: ## List targets.
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

.PHONY: build
build: ## Build the CLI into bin/.
	go build -ldflags "$(LDFLAGS)" -o bin/tessera-sign ./cmd/tessera-sign

.PHONY: test
test: fmt vet ## Run the tests with the race detector.
	go test ./... -race

.PHONY: crypto
crypto: ## Run only the adversarial signature cases, verbosely.
	go test ./internal/bundle -run 'TestVerifyRejects|TestVerifyRequires|TestSuiteIsAuthenticated|TestSignedTimestamp' -v

.PHONY: fmt
fmt: ## Format the source.
	gofmt -w .

.PHONY: vet
vet: ## Run go vet.
	go vet ./...

.PHONY: clean
clean: ## Remove build output.
	rm -rf bin
