.PHONY: build
build:
	go build

.PHONY: examples
examples: example/http

example/%: example/%.go
	go build -o $@ $<

.PHONY: test
test:
	go test -coverprofile cover.out

.PHONY: coverage
coverage: test
	go tool cover -html cover.out