SHELL=/bin/bash
container_name=go-authenticator

.PHONY: bin build test start stop
bin:
	go build -a -tags "netgo" -installsuffix netgo  -ldflags="-s -w -extldflags \"-static\" \
	-X main.version=$(git describe --tag --abbrev=0) \
	-X main.revision=$(git rev-list -1 HEAD) \
	-X main.build=$(git describe --tags)" \
	-o ./build/bin/ ./...

build:
	docker build -t $(container_name):latest -f build/Dockerfile .

test: 
	(! gofmt -s -d . | grep '^') 
	go vet ./...
	staticcheck ./...
	go test -v ./...

start:
	docker compose -f deployment/compose.yml up -d

stop:
	docker compose -f deployment/compose.yml down
