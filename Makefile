.PHONY: build test lint clean

build:
	go build -o call-policy-default ./cmd/module

test:
	go test -race -count=1 ./...

lint:
	golangci-lint run

clean:
	rm -f call-policy-default
	rm -f cmd/module/module
