.PHONY: test vet fmt build check

test:
	go test ./...

vet:
	go vet ./...

fmt:
	@test -z "$$(gofmt -l .)" || (gofmt -l . && exit 1)

build:
	mkdir -p bin
	go build -o bin/aws-audit ./cmd/aws-audit
	go build -o bin/aws-audit-summarize ./cmd/aws-audit-summarize

check: fmt vet test
