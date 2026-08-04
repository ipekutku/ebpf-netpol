.PHONY: generate build vet run clean

generate:
	go generate ./...

build: generate
	go build -o bin/netguard ./cmd/netguard

vet: generate
	go vet ./...

run: build
	sudo ./bin/netguard

clean:
	rm -rf bin internal/execsnoop/bpf_bpfe*.go internal/execsnoop/bpf_bpfe*.o
