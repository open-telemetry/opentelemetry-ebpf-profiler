.PHONY: build clean lint test vuln-check

build:
	go build ./cmd/strobelight-ctrl

clean:
	go clean -cache -i
	rm strobelight-ctrl

lint:
	go tool staticcheck -checks=all ./...

test:
	go test ./...

vuln-check:
	go tool govulncheck ./...
