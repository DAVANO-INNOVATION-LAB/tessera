# Tessera — offline AIBOM generator for model files.
#
# One analyser, shipped in four shapes so anything can embed it:
#
#   library   go get + import          (Go callers — no process, no container)
#   cli       a static binary          (anything that can exec)
#   ffi       .so / .dylib / .dll      (Python, Rust, Java, C#, Node — in-process)
#   wasm      .wasm (WASI + browser)   (sandboxed and browser runtimes)

VERSION ?= dev
LDFLAGS := -X main.version=$(VERSION)
LIBFLAGS := -X main.version=$(VERSION)
PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64

# c-shared library extension per host OS.
UNAME := $(shell uname -s)
ifeq ($(UNAME),Darwin)
  LIBEXT := dylib
else ifeq ($(OS),Windows_NT)
  LIBEXT := dll
else
  LIBEXT := so
endif

.PHONY: help
help: ## List targets.
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

.PHONY: build
build: ## Build the tessera CLI into bin/.
	go build -ldflags "$(LDFLAGS)" -o bin/tessera ./cmd/tessera

.PHONY: ffi
ffi: ## Build the C shared library + header into bin/ (for non-Go embedders).
	go build -buildmode=c-shared -ldflags "$(LIBFLAGS)" \
		-o bin/libtessera.$(LIBEXT) ./cmd/libtessera
	@echo "  bin/libtessera.$(LIBEXT) + bin/libtessera.h"

.PHONY: wasm
wasm: ## Build the WASI and browser WebAssembly modules into bin/.
	GOOS=wasip1 GOARCH=wasm go build -ldflags "$(LDFLAGS)" -o bin/tessera.wasm ./cmd/tessera
	GOOS=js GOARCH=wasm go build -ldflags "$(LDFLAGS)" -o bin/tessera-js.wasm ./cmd/tessera
	@echo "  bin/tessera.wasm (WASI)  bin/tessera-js.wasm (browser)"

.PHONY: all
all: build ffi wasm ## Build every distribution shape.

.PHONY: test
test: fmt vet ## Run the test suite with the race detector.
	go test ./... -race

.PHONY: fmt
fmt: ## Format the source.
	gofmt -w .

.PHONY: vet
vet: ## Run go vet.
	go vet ./...

.PHONY: cover
cover: ## Test with a coverage profile.
	go test ./... -coverprofile=cover.out
	go tool cover -func=cover.out | tail -1

.PHONY: verify-embed
verify-embed: ## Re-check the embedding guarantees (no deps, no net, no output).
	go test . -run 'TestNo|TestAnalysisWrites' -v

.PHONY: release
release: ## Cross-compile CLI release binaries into dist/.
	@mkdir -p dist
	@for p in $(PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; ext=; [ "$$os" = windows ] && ext=.exe; \
		echo "  $$os/$$arch"; \
		GOOS=$$os GOARCH=$$arch go build -ldflags "$(LDFLAGS)" \
			-o dist/tessera-$$os-$$arch$$ext ./cmd/tessera; \
	done

.PHONY: clean
clean: ## Remove build output.
	rm -rf bin dist cover.out
