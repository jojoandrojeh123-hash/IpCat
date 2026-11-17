.PHONY: test server server-amd64 server-arm64 client

ifeq ($(OS),Windows_NT)
CLIENT_OUTPUT = mcwatch-client.exe
CLIENT_LDFLAGS = -ldflags "-H=windowsgui"
else
CLIENT_OUTPUT = mcwatch-client
CLIENT_LDFLAGS =
endif

test:
	go test -race ./...

server: server-amd64 server-arm64

server-amd64:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o mcwatch-server-linux-amd64 ./cmd/server

server-arm64:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o mcwatch-server-linux-arm64 ./cmd/server

client:
	go build $(CLIENT_LDFLAGS) -o $(CLIENT_OUTPUT) ./cmd/client
