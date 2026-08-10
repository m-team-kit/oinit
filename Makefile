OUT=./bin
VERSION=$(shell cat VERSION)

.PHONY: all oinit oinit-ca oinit-shell oinit-switch oinit-ca-docker swagger man clean

all: oinit oinit-ca oinit-shell oinit-switch

# Build the whole package (./cmd/<name>), not a single .go file: some binaries
# (e.g. oinit) are split across multiple files, including platform-specific ones
# selected via build tags. A single-file `go build .../foo.go` would miss those
# siblings and fail to compile.
oinit:
	go build -ldflags="-s -w -X main.version=$(VERSION)" -o ${OUT}/oinit ./cmd/oinit

oinit-ca:
	go build -ldflags="-s -w" -o ${OUT}/oinit-ca ./cmd/oinit-ca

oinit-shell:
	go build -ldflags="-s -w" -o ${OUT}/oinit-shell ./cmd/oinit-shell

oinit-switch:
	go build -ldflags="-s -w" -o ${OUT}/oinit-switch ./cmd/oinit-switch

# Generate roff man pages (and gzipped copies) from man/*.md via go-md2man.
# The same script is run by the goreleaser `before` hook at package time.
man:
	./scripts/gen-manpages.sh

oinit-ca-docker:
	docker build -f build/Dockerfile -t oinit-ca .

swagger:
	swag init --parseInternal -g cmd/oinit-ca/oinit-ca.go -o api/docs/
	swag fmt -d internal/api/

clean:
	rm -rf ./bin
	rm -f man/*.1 man/*.5 man/*.8 man/*.gz
