.PHONY: build image 

# Prepend our vendor directory to the system GOPATH
# so that import path resolution will prioritize
# our third party snapshots.
export GO15VENDOREXPERIMENT=1
# GOPATH := ${PWD}/vendor:${GOPATH}
# export GOPATH

default: build

build:
	docker run --rm \
                -e CGO_ENABLED=0 -e GOOS=linux -e GOARCH=amd64  \
                -v $(shell pwd):/go/src/github.com/gorilla001/ftptool \
                -w /go/src/github.com/gorilla001/ftptool \
                golang:1.8.1-alpine \
                sh -c 'go build -v'

image: build
	docker build --rm --tag ftptool:$(shell git rev-parse --short HEAD) .

