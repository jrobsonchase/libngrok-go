.PHONY: build
build:
	go build

.PHONY: examples
examples: example/http

.PHONY: run-example-%
run-example-%:
	go run example/$*.go

.PHONY: example/%
example/%: example/%.go
	go build -o $@ $<

.PHONY: test
test:
	go test -coverprofile cover.out

.PHONY: coverage
coverage: test
	go tool cover -html cover.out