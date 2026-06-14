BINARY := dns
VHS := vhs

.PHONY: build run test fmt vet clean gif screenshots assets

build:
	go build -o $(BINARY) .

run: build
	./$(BINARY)

test:
	go test ./...

fmt:
	go fmt ./...

vet:
	go vet ./...

clean:
	rm -f $(BINARY)

gif:
	$(VHS) vhs/cassette.tape

screenshots:
	$(VHS) vhs/screenshots.tape

assets: gif screenshots
