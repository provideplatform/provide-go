.PHONY: build clean install mod lint test generate-ts-types

clean:
	go fix ./...
	go clean -i ./...

build: clean mod
	go fmt ./...
	CGO_CFLAGS=-Wno-undef-prefix go build ./...

lint:
	./ops/lint.sh

mod:
	go mod init 2>/dev/null || true
	go mod tidy
	go mod vendor 

test: build
	go test -v -race ./api
	go test -v -race ./common
	go test -v -race ./crypto

generate-ts-types:
	./ops/generate-ts-types.sh