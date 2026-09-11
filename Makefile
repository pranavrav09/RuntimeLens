BINARY := runtimelens
BIN_DIR := bin
BPF_OBJECT := internal/collector/runtimelens_bpfel.o

.PHONY: all generate check-core build test vet ci clean check-linux

all: build

check-linux:
	@test "$$(uname -s)" = Linux || { echo "RuntimeLens eBPF generation requires Linux" >&2; exit 1; }

generate: check-linux
	go generate ./internal/collector

check-core: generate
	@test -f $(BPF_OBJECT)
	@llvm-readelf -S $(BPF_OBJECT) | grep -q '\.BTF'
	@llvm-readelf -S $(BPF_OBJECT) | grep -q '\.BTF\.ext'
	@echo "CO-RE metadata present in $(BPF_OBJECT)"

build: generate
	mkdir -p $(BIN_DIR)
	go build -trimpath -ldflags='-s -w' -o $(BIN_DIR)/$(BINARY) ./cmd/runtimelens

test: generate
	go test -race ./...

vet: generate
	go vet ./...

ci: check-core build
	go test -race ./...
	go vet ./...

clean:
	rm -rf $(BIN_DIR)
	rm -f internal/collector/*_bpfel.go internal/collector/*_bpfel.o
	rm -f internal/collector/*_bpfeb.go internal/collector/*_bpfeb.o
