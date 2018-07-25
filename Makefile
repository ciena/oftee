
help:
	@echo "test       : runs static and golang tests"

PACKAGES=github.com/ciena/oftee github.com/ciena/oftee/criteria github.com/ciena/oftee/api github.com/ciena/oftee/connections github.com/ciena/oftee/injector

.PHONY: image
image:
	docker build --rm -t oftee .

.PHONY: build
build:
	docker run -ti --rm -v $(shell pwd)/:/go/src/github.com/ciena/oftee golang:1.9-alpine go build github.com/ciena/oftee

.PHONY: run
run:
	docker run -ti --rm -v $(shell pwd)/:/go/src/github.com/ciena/oftee golang:1.9-alpine go run /go/src/github.com/ciena/oftee/oftee.go

.PHONY: tests
tests: vet lint errcheck utests itests

.PHONY: vet
vet:
	docker run -ti --rm -v $(shell pwd)/:/go/src/github.com/ciena/oftee golang:1.9-alpine go vet github.com/ciena/oftee/...

.PHONY: utests
utests:
	docker run -ti --rm -v $(shell pwd)/:/go/src/github.com/ciena/oftee golang:1.9-alpine go test github.com/ciena/oftee/...

.PHONY: itests
itests:
	@echo "integration tests are not yet implemented"

.PHONY: lint
lint:
	docker run -ti --rm -v $(shell pwd)/:/go/src/github.com/ciena/oftee ciena/go-lint

.PHONY: errcheck
errcheck:
	docker run -ti --rm -v $(shell pwd)/:/go/src/github.com/ciena/oftee ciena/go-errcheck

