.PHONY: all build certgen test run clean

all: build

build:
	mkdir -p bin
	go build -o bin/server ./cmd/server
	go build -o bin/certgen ./cmd/certgen

certgen: build
	./bin/certgen -out-dir certs -force

test:
	go test -v -race ./...

run: build
	./bin/server

clean:
	rm -rf bin
