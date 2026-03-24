VERSION ?= dev
LDFLAGS  = -ldflags "-X github.com/agentOnRails/agent-on-rails/internal/version.Version=$(VERSION)"
GOTEST   = go test -count=1

.PHONY: build test test-e2e test-sepolia vet clean testserver

## build: compile the aor binary
build:
	go build $(LDFLAGS) -o aor ./cmd/aor/

## test: run unit + integration tests (no daemon, no real chain)
test:
	$(GOTEST) ./internal/... ./test/integration/

## test-e2e: run full daemon e2e tests (mock upstream, no real chain)
test-e2e:
	$(GOTEST) ./test/e2e/ -v -timeout=120s

## test-sepolia: run real Base Sepolia chain tests (requires funded wallet)
##   Requires: TEST_SEPOLIA=1  AOR_TEST_PRIVATE_KEY=0x...  AOR_TEST_PAYTO=0x...
test-sepolia:
	TEST_SEPOLIA=1 $(GOTEST) ./test/e2e/ -run TestSepolia -v -timeout=120s

## vet: run go vet
vet:
	go vet ./...

## clean: remove build artifacts
clean:
	rm -f aor aor.exe

## testserver: run the local x402-compliant test API server
##   Usage: make testserver PAYTO=0xYOUR_WALLET
testserver:
	go run ./scripts/testserver/ -payto $(PAYTO)
